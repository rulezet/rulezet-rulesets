rule sig_20160302_03a9d2d5895625bea43dc89328879083 {
  meta:
    description = "datamaliciousorder - file 20160302_03a9d2d5895625bea43dc89328879083.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37df45fde7ca656a9f7b7d945fed69a9f409946768fef67942127dd6d055a883"

  strings:
    $s1  = "            return r < 128 ? e : r < 2048 ? i(192 | r >>> 6) + i(128 | 63 & r) : i(224 | r >>> 12 & 15) + i(128 | r >>> 6 & 63) " ascii
    $s2  = "            return i(240 | r >>> 18 & 7) + i(128 | r >>> 12 & 63) + i(128 | r >>> 6 & 63) + i(128 | 63 & r);" fullword ascii
    $s3  = "            return i((t >>> 10) + 55296) + i((1023 & t) + 56320);" fullword ascii
    $s4  = "            return r < 128 ? e : r < 2048 ? i(192 | r >>> 6) + i(128 | 63 & r) : i(224 | r >>> 12 & 15) + i(128 | r >>> 6 & 63) " ascii
    $s5  = "        return WScript[r](e);" fullword ascii
    $s6  = "var endemicRem = function(e) {" fullword ascii
    $s7  = "!function(e) {" fullword ascii
    $s8  = "var striateUGE = function() {" fullword ascii
    $s9  = "    var d = String[\"f\" + \"r\" + \"o\" + \"mCharCode\"];" fullword ascii
    $s10 = "        VERSION: t," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}
rule sig_20160302_c4c45df3832cde7bbc1bb529d22a5cbb {
  meta:
    description = "datamaliciousorder - file 20160302_c4c45df3832cde7bbc1bb529d22a5cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e46574516aad9e1d6965a21d44fc358e4705d2f8a07db81030b252094e527242"

  strings:
    $s1 = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s2 = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s3 = "            return u((t >>> 10) + 55296) + u((1023 & t) + 56320);" fullword ascii
    $s4 = "            return u(240 | e >>> 18 & 7) + u(128 | e >>> 12 & 63) + u(128 | e >>> 6 & 63) + u(128 | 63 & e);" fullword ascii
    $s5 = "        return WScript[e](r);" fullword ascii
    $s6 = "var effervescencenWt = function() {" fullword ascii
    $s7 = "    var p = String[\"fr\" + \"om\" + \"Cha\" + \"rCode\"];" fullword ascii
    $s8 = "        VERSION: t," fullword ascii
    $s9 = "var scarcewSf = function(r) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}
rule sig_20160301_f5523fad80c6eae864ec31211bc48eef {
  meta:
    description = "datamaliciousorder - file 20160301_f5523fad80c6eae864ec31211bc48eef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8940282a2fad6670a4a9b0c1a86d29f2322ddbb5efe8380f0e4d3d500d85e5e"

  strings:
    $s1 = "aviationDiagram = (((127 & 114), (183 - 112), 1), this);" fullword ascii
    $s2 = "examineAtom = amorphousRecommend[(\"\\u0074i\" + \"\\u0063\\u006b\", function String.prototype.mileConception() {" fullword ascii
    $s3 = "while(artistHumane[(\"\\u0072\" + \"e\\u0061\\u0064y\\u0073\" + \"\\u0074\\u0061\\u0074e\")] < (2 & 3) * (0 + 2)) {" fullword ascii
    $s4 = "} catch(scalpelIdentical) {};" fullword ascii

  condition:
    uint16(0) == 0x7661 and
    all of them
}
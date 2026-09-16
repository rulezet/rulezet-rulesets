rule sig_20160823_9683326d08b5708098897f4b51e7a7e0 {
  meta:
    description = "datamaliciousorder - file 20160823_9683326d08b5708098897f4b51e7a7e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a3288c4d8942fd985f5abf26de0a1e85f81b4eea763937e07b9044387177903"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
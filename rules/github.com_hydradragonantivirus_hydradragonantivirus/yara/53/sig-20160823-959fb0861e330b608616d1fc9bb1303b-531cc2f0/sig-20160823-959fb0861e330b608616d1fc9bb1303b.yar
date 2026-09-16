rule sig_20160823_959fb0861e330b608616d1fc9bb1303b {
  meta:
    description = "datamaliciousorder - file 20160823_959fb0861e330b608616d1fc9bb1303b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354ef5ab40edce886ed7be479db078aeb1cb94d9d74a918448c0218570965971"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
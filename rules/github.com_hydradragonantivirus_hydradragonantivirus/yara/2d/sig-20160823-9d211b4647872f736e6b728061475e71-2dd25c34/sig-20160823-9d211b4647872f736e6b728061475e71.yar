rule sig_20160823_9d211b4647872f736e6b728061475e71 {
  meta:
    description = "datamaliciousorder - file 20160823_9d211b4647872f736e6b728061475e71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2478f15b82aa19a4390faae31309a853dbe0d4d68a2542805532c32fc258223c"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
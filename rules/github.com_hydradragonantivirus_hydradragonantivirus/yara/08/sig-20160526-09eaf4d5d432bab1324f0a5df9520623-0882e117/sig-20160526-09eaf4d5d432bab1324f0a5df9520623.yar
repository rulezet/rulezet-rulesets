rule sig_20160526_09eaf4d5d432bab1324f0a5df9520623 {
  meta:
    description = "datamaliciousorder - file 20160526_09eaf4d5d432bab1324f0a5df9520623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0d6f058322c60c0c063c3a30b8f43c9ff36804cfc3deefda0b41b1454bd66b5"

  strings:
    $s1 = "KELP rav\\n;\"Ae46x\\\\oC\" = h8fGRBSXG rav\\n;)5(]\"tA\"+\"27x\\\\\"+\"ahc\"[c7wGKPFTL = s5rZAFQBR rav;\"otyDl9R\" = c7wGKPFTL " ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}
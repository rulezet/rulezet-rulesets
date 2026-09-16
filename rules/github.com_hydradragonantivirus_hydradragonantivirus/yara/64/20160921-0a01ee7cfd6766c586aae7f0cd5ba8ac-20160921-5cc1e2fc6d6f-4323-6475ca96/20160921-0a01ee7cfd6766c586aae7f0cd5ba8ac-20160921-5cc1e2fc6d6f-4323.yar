rule _20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac_20160921_5cc1e2fc6d6f_4323 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"
    hash2       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"

  strings:
    $s1 = " fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IP" ascii
    $s2 = "Oj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(functi" ascii
    $s3 = ",(function fuck(){return \"BGe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii
    $s4 = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function " ascii
    $s5 = "n \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
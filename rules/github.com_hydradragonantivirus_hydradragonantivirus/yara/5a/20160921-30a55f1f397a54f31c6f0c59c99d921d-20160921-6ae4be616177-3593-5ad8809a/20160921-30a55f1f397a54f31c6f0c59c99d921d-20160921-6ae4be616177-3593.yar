rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_6ae4be616177_3593 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash3       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"

  strings:
    $s1 = "k(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\"" ascii
    $s2 = "urn \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s3 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZWu\";})(),(fu" ascii
    $s4 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ot\";})(),(function fuck" ascii
    $s5 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s6 = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
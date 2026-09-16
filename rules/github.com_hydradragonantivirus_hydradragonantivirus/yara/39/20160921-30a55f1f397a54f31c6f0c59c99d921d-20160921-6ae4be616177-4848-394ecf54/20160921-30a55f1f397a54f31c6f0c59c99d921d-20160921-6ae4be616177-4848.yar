rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_6ae4be616177_4848 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash3       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1 = "k(){return \"Ai\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IRn\";" ascii
    $s2 = " fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s3 = "turn \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s4 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){r" ascii
    $s5 = "})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Cd\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
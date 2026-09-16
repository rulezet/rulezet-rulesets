rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_5181 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash3       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"

  strings:
    $s1 = " fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IR" ascii
    $s2 = " \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s3 = "eturn \"Ug\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s4 = "k(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\"" ascii
    $s5 = " fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"V" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
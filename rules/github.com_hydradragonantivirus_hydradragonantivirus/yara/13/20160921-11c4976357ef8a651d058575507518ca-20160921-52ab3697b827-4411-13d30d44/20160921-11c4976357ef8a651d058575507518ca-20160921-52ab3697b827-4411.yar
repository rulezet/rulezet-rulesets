rule _20160921_11c4976357ef8a651d058575507518ca_20160921_52ab3697b827_4411 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash3       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash4       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1 = "\"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s2 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(functi" ascii
    $s3 = "unction fuck(){return \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s4 = "(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\"" ascii
    $s5 = "(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
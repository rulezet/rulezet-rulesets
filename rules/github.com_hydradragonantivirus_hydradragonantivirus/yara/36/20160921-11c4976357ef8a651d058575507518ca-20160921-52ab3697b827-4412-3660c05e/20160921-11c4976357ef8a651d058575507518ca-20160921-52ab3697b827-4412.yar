rule _20160921_11c4976357ef8a651d058575507518ca_20160921_52ab3697b827_4412 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash3       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash4       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash5       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "){return \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s2 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"To\";})(),(functio" ascii
    $s3 = "fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve" ascii
    $s4 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){retur" ascii
    $s5 = "function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
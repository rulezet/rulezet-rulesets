rule _20160921_52ab3697b827675e3be965f7171e236d_20160921_8644cb559dff_5180 {
  meta:
    description = "datamaliciousorder - from files 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash2       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash3       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s2 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(" ascii
    $s3 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Av\";})()" ascii
    $s4 = "n fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "ck(){return \"We\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
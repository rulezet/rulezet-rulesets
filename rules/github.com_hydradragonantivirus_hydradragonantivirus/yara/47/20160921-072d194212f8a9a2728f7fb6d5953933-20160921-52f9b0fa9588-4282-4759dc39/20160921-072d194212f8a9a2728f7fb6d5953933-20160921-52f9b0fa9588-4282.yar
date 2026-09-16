rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_4282 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash4       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1 = "urn \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(f" ascii
    $s2 = "ction fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return" ascii
    $s3 = "fuck(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs" ascii
    $s4 = "(function fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s5 = "MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
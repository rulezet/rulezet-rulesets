rule _20160921_5cabcf77c626e288d5cbd9104a914ae8_20160921_d97203a3a0e9_5245 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cabcf77c626e288d5cbd9104a914ae8.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"
    hash2       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1 = "fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Fv" ascii
    $s2 = "(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){re" ascii
    $s3 = "turn \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s4 = "n \"OQr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"MOj\";})(),(f" ascii
    $s5 = "),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
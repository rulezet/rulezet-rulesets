rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_22511056ddb6_2224 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash3       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash4       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"
    hash5       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash6       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"
    hash7       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash8       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1 = ",(function fuck(){return \"Av\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s2 = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"EHo\";})(),(function fuc" ascii
    $s3 = " \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Fv\";})(),(funct" ascii
    $s4 = "){return \"GJx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"RAi\";}" ascii
    $s5 = " \"Nm\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s6 = "(function fuck(){return \"Vf\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){r" ascii
    $s7 = "k(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ar\";}" ascii
    $s8 = "ction fuck(){return \"Fv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_6ae4be616177_2033 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_718cbfc32cb1f435745a5a005d3f190b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash3       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"

  strings:
    $s1 = "\"Xw\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s2 = " fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"" ascii
    $s3 = " fuck(){return \"DAa\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"I" ascii
    $s4 = "n \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s5 = "\"DWe\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s6 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retur" ascii
    $s7 = "nction fuck(){return \"GJx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){retu" ascii
    $s8 = "ck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt" ascii
    $s9 = "uck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"UOe" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
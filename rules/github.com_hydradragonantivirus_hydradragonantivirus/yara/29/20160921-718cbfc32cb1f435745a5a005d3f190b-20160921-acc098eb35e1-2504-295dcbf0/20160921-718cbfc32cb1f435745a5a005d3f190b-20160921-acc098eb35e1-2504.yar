rule _20160921_718cbfc32cb1f435745a5a005d3f190b_20160921_acc098eb35e1_2504 {
  meta:
    description = "datamaliciousorder - from files 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash2       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash3       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1 = "),(function fuck(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){" ascii
    $s2 = "k(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\"" ascii
    $s3 = "Hs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s4 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"" ascii
    $s5 = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";}" ascii
    $s6 = "k(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"EHo\"" ascii
    $s7 = "XFd\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(functio" ascii
    $s8 = "u\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
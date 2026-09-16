rule _20160921_7ab823078d2353d978403d071ad27626_20160921_82861e992460_1899 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js, 20160921_99220520e87414c0f2e1267cf4078a22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash2       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"
    hash3       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"

  strings:
    $s1  = "function fuck(){return \"Ot\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s2  = "n \"Ug\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s3  = "ck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx" ascii
    $s4  = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Av" ascii
    $s5  = " \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s6  = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){" ascii
    $s7  = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ZL" ascii
    $s8  = "){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})" ascii
    $s9  = ",(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck()" ascii
    $s10 = "uck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
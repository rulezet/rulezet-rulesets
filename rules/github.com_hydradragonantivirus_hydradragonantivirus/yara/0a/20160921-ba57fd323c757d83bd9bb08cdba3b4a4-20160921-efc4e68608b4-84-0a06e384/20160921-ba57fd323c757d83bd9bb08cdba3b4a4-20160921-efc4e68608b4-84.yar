rule _20160921_ba57fd323c757d83bd9bb08cdba3b4a4_20160921_efc4e68608b4_84 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash2       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1  = "rn \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s2  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s3  = " \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\";})(),(func" ascii
    $s4  = "o\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s5  = "nction fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){retur" ascii
    $s6  = "n \"Np\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s7  = "d\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s8  = ")(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck" ascii
    $s9  = "return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(" ascii
    $s10 = "(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){" ascii
    $s11 = "fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg" ascii
    $s12 = "n \"DRx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(f" ascii
    $s13 = "IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s14 = "tion fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s15 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ar\";})(),(function fuck()" ascii
    $s16 = "uck(){return \"AUx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s17 = "ion fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return" ascii
    $s18 = "return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(" ascii
    $s19 = " \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s20 = "k(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
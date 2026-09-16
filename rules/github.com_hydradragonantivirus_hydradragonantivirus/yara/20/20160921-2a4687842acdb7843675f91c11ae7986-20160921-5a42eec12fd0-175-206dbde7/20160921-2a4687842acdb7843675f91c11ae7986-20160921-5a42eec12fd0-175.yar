rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_5a42eec12fd0_175 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash3       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1  = "urn \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s2  = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){ret" ascii
    $s3  = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Oh\";})(" ascii
    $s4  = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(functio" ascii
    $s5  = "k(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";" ascii
    $s6  = "urn \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GWo\";})(),(" ascii
    $s7  = "n \"Ai\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s8  = "n \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(fun" ascii
    $s9  = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retu" ascii
    $s10 = "})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii
    $s11 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Jh\";})(),(f" ascii
    $s12 = "eturn \"Xw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s13 = "(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})" ascii
    $s14 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(funct" ascii
    $s15 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ZLd\";})" ascii
    $s16 = "rn \"Xg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Jo\";})(),(fun" ascii
    $s17 = "})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s18 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"X" ascii
    $s19 = "k(){return \"Nm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\"" ascii
    $s20 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"MIl\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
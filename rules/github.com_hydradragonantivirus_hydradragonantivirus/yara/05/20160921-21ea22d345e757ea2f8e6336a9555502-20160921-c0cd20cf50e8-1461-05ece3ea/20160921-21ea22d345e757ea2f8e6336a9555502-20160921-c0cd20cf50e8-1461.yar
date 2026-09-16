rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_c0cd20cf50e8_1461 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"

  strings:
    $s1  = ",(function fuck(){return \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s2  = "IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(functi" ascii
    $s3  = "n \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(fun" ascii
    $s4  = "return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})" ascii
    $s5  = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";" ascii
    $s6  = "(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck" ascii
    $s7  = "{return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(" ascii
    $s8  = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})()," ascii
    $s9  = "(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s10 = "tion fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){retur" ascii
    $s11 = "w\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function f" ascii
    $s12 = "Ts\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii
    $s13 = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
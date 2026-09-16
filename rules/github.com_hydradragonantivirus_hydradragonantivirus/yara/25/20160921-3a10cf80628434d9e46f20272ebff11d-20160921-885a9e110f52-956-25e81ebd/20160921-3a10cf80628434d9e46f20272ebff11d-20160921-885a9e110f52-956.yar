rule _20160921_3a10cf80628434d9e46f20272ebff11d_20160921_885a9e110f52_956 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a10cf80628434d9e46f20272ebff11d.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c217c4eb7bba8a6770bdd6609635a67fc8772b37668310875b4f4f1ff0b472c2"
    hash2       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash3       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"

  strings:
    $s1  = "{return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})" ascii
    $s2  = "ck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";" ascii
    $s3  = "{return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})" ascii
    $s4  = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function " ascii
    $s5  = ")(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s6  = "rn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(f" ascii
    $s7  = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"" ascii
    $s8  = "urn \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(f" ascii
    $s9  = "){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s10 = "on fuck(){return \"YAv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s11 = "eturn \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Wo\";})()" ascii
    $s12 = "nction fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return" ascii
    $s13 = "n \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s14 = "fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"S" ascii
    $s15 = "(){return \"ZLd\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"PDf\";}" ascii
    $s16 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function fuck()" ascii
    $s17 = "})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fu" ascii
    $s18 = "n \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Pc\";})(),(fun" ascii
    $s19 = "fuck(){return \"Vf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s20 = "\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IRn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
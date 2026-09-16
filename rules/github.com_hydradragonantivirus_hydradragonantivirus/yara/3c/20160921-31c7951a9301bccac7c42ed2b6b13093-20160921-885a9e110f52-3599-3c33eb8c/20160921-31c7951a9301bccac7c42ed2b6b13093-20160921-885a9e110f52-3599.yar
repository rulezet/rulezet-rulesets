rule _20160921_31c7951a9301bccac7c42ed2b6b13093_20160921_885a9e110f52_3599 {
  meta:
    description = "datamaliciousorder - from files 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash2       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash3       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(" ascii
    $s2 = "n \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s3 = "{return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})()," ascii
    $s4 = "n fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"" ascii
    $s5 = "n \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s6 = ")(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
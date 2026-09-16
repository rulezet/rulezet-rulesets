rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_8b272d3350b6_4461 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"

  strings:
    $s1 = "\"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(funct" ascii
    $s2 = "uck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"FJs" ascii
    $s3 = "{return \"XFd\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IRn\";})" ascii
    $s4 = "nction fuck(){return \"Ot\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){retur" ascii
    $s5 = "{return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"KVh\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
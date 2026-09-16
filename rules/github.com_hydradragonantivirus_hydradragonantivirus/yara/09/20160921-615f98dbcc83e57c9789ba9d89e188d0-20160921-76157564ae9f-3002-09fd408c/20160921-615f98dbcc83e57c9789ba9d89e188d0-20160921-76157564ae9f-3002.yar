rule _20160921_615f98dbcc83e57c9789ba9d89e188d0_20160921_76157564ae9f_3002 {
  meta:
    description = "datamaliciousorder - from files 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_76157564ae9f7ad7ec97100684b2a5ce.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash2       = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"
    hash3       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1 = "){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"EHo\";}" ascii
    $s2 = "d\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function " ascii
    $s3 = "){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";}" ascii
    $s4 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";})(" ascii
    $s5 = ";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii
    $s6 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo" ascii
    $s7 = "(function fuck(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
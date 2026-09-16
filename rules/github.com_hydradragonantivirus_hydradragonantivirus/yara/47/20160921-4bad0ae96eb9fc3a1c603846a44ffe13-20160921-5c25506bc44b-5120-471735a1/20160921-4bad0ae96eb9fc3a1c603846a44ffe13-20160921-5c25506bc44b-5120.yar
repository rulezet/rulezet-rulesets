rule _20160921_4bad0ae96eb9fc3a1c603846a44ffe13_20160921_5c25506bc44b_5120 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_8c8c9fad8af659443108d1078847a668.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash2       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash3       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash4       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"
    hash5       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1 = "function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){ret" ascii
    $s2 = "uck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Za" ascii
    $s3 = "g\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function" ascii
    $s4 = "n \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(fu" ascii
    $s5 = "),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
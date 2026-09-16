rule _20160921_8c8c9fad8af659443108d1078847a668_20160921_99220520e874_3974 {
  meta:
    description = "datamaliciousorder - from files 20160921_8c8c9fad8af659443108d1078847a668.js, 20160921_99220520e87414c0f2e1267cf4078a22.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"
    hash2       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"
    hash3       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "turn \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})()," ascii
    $s2 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return " ascii
    $s3 = "e\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s4 = "fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\"" ascii
    $s5 = "unction fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii
    $s6 = "eturn \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
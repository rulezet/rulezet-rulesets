rule _20160921_0298568f245d937dde081d505d360a5e_20160921_21041f3360c4_123 {
  meta:
    description = "datamaliciousorder - from files 20160921_0298568f245d937dde081d505d360a5e.js, 20160921_21041f3360c455bf09d8b48dda6959f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f31455e0194491e66143329dadae1760f33af4219844671541520909cf32d58"
    hash2       = "de559d9fde4fb08962605e84afb3f8e86d21c757f1189b673ed0648e3dd75cd0"

  strings:
    $s1  = "),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(function fuck()" ascii
    $s2  = "t\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s3  = "k(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";" ascii
    $s4  = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s5  = "nction fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii
    $s6  = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})()," ascii
    $s7  = "\"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(funct" ascii
    $s8  = "e\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function " ascii
    $s9  = "(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";" ascii
    $s10 = "})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"GNm\";})(),(function fuck" ascii
    $s11 = "n \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s12 = "urn \"Ar\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s13 = "return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OPz\";})()" ascii
    $s14 = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return " ascii
    $s15 = "eturn \"QTc\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})()" ascii
    $s16 = "(function fuck(){return \"DWe\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s17 = "urn \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(fun" ascii
    $s18 = "IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s19 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Py\";})(),(function fuck(" ascii
    $s20 = "nction fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
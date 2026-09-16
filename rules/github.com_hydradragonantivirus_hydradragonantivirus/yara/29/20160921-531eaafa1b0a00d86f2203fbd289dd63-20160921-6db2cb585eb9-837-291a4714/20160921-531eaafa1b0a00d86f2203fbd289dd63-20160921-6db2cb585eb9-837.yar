rule _20160921_531eaafa1b0a00d86f2203fbd289dd63_20160921_6db2cb585eb9_837 {
  meta:
    description = "datamaliciousorder - from files 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash2       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"

  strings:
    $s1  = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s2  = "ion fuck(){return \"YQt\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii
    $s3  = "})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s4  = " fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe" ascii
    $s5  = ",(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){" ascii
    $s6  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(" ascii
    $s7  = "Wu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s8  = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){retur" ascii
    $s9  = "return \"YQt\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s10 = " \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s11 = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retur" ascii
    $s12 = "(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"TTs\";" ascii
    $s13 = ";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s14 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function " ascii
    $s15 = "u\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s16 = "function fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s17 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retur" ascii
    $s18 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(funct" ascii
    $s19 = " fuck(){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s20 = "eturn \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
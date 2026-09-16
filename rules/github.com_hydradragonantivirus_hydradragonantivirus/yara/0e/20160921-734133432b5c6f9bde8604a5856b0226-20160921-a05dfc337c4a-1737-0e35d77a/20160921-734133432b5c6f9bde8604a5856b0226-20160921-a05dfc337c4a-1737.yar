rule _20160921_734133432b5c6f9bde8604a5856b0226_20160921_a05dfc337c4a_1737 {
  meta:
    description = "datamaliciousorder - from files 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_a05dfc337c4ada28e05759b304eef904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash2       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"

  strings:
    $s1  = "n \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(fun" ascii
    $s2  = "fuck(){return \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DRx" ascii
    $s3  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"" ascii
    $s4  = " fuck(){return \"Ve\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz" ascii
    $s5  = "(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck" ascii
    $s6  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return" ascii
    $s7  = "CTm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(functio" ascii
    $s8  = "n \"Jo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s9  = "n fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"" ascii
    $s10 = "),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s11 = "on fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
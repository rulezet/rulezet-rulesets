rule _20160921_76157564ae9f7ad7ec97100684b2a5ce_20160921_8881f4de1f94_308 {
  meta:
    description = "datamaliciousorder - from files 20160921_76157564ae9f7ad7ec97100684b2a5ce.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"
    hash2       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash3       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"
    hash4       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1  = "(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(" ascii
    $s2  = "{return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";}" ascii
    $s3  = " fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s4  = ")(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck" ascii
    $s5  = " \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s6  = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s7  = "k(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\"" ascii
    $s8  = "k(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";" ascii
    $s9  = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s10 = "ction fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retur" ascii
    $s11 = "fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe" ascii
    $s12 = "Kv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii
    $s13 = "(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s14 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s15 = "function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){re" ascii
    $s16 = "{return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})()," ascii
    $s17 = "){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";}" ascii
    $s18 = "turn \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(" ascii
    $s19 = "on fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"" ascii
    $s20 = "on fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
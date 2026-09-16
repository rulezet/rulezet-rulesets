rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_9bf90f0e5e3e_1440 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash3       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1  = "\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s2  = "WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(functio" ascii
    $s3  = "\"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(functio" ascii
    $s4  = "){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})" ascii
    $s5  = "){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Fs\";})" ascii
    $s6  = "000(){return \"SGs\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s7  = "Sj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s8  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oe" ascii
    $s9  = "Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s10 = "000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s11 = "turn \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s12 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"PTs\";})(),(fu" ascii
    $s13 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DAp\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
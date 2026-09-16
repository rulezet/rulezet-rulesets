rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_77c9e00128c9_1580 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"

  strings:
    $s1  = "turn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(" ascii
    $s2  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"HJm\";})(),(function f0" ascii
    $s3  = "(){return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})" ascii
    $s4  = "nction f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s5  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s6  = "eturn \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s7  = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(func" ascii
    $s8  = "h\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s9  = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Qa\";" ascii
    $s10 = "00(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s11 = "nction f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(){retur" ascii
    $s12 = "unction f000(){return \"Qa\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
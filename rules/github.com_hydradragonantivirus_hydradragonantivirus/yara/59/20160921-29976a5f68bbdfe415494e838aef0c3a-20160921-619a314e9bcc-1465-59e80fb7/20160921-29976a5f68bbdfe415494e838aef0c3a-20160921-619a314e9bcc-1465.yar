rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_619a314e9bcc_1465 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash3       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"

  strings:
    $s1  = "})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s2  = "unction f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(function f000(){ret" ascii
    $s3  = "f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"V" ascii
    $s4  = "eturn \"Lp\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})()" ascii
    $s5  = "{return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})" ascii
    $s6  = "unction f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s7  = ",(function f000(){return \"Lp\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(){" ascii
    $s8  = "){return \"Yv\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(" ascii
    $s9  = "0(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";}" ascii
    $s10 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})()" ascii
    $s11 = " f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s12 = "tion f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s13 = "rn \"Qa\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"WIj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
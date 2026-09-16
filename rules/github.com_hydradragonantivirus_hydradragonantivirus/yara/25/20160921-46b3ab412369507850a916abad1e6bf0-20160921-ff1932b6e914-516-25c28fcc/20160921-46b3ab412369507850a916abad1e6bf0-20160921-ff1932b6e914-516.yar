rule _20160921_46b3ab412369507850a916abad1e6bf0_20160921_ff1932b6e914_516 {
  meta:
    description = "datamaliciousorder - from files 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash2       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1  = "f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qz" ascii
    $s2  = "(),(function f000(){return \"Uo\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){" ascii
    $s3  = "turn \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(f" ascii
    $s4  = "00(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\"" ascii
    $s5  = "})(),(function f000(){return \"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f0" ascii
    $s6  = "tion f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s7  = "00(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Uo\";" ascii
    $s8  = "urn \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(f" ascii
    $s9  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){retu" ascii
    $s10 = ";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f00" ascii
    $s11 = "0(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\"" ascii
    $s12 = "(),(function f000(){return \"Ml\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Oe\";})(),(function f000()" ascii
    $s13 = "n f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s14 = "{return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";}" ascii
    $s15 = "ction f000(){return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){retur" ascii
    $s16 = "y\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mt\";})(),(function" ascii
    $s17 = "function f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){retu" ascii
    $s18 = "ion f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"" ascii
    $s19 = "\"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s20 = "eturn \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
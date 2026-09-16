rule _20160921_4aeb02b393c6ed3fdeadcb6a29499bfc_20160922_e3f5fbc84de1_398 {
  meta:
    description = "datamaliciousorder - from files 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1  = "Ij\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s2  = "turn \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(" ascii
    $s3  = "(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Qz\";})(" ascii
    $s4  = "ction f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s5  = "ion f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s6  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){retur" ascii
    $s7  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii
    $s8  = "rn \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s9  = "u\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function" ascii
    $s10 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s11 = "on f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s12 = "0(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";" ascii
    $s13 = "urn \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s14 = "urn \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s15 = "{return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(" ascii
    $s16 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000()" ascii
    $s17 = "on f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s18 = "nction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s19 = "000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu" ascii
    $s20 = "function f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
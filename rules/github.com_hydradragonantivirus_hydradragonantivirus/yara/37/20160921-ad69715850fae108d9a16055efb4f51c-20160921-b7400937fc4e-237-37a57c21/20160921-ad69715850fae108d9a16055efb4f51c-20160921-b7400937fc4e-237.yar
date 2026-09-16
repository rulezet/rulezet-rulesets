rule _20160921_ad69715850fae108d9a16055efb4f51c_20160921_b7400937fc4e_237 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad69715850fae108d9a16055efb4f51c.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"

  strings:
    $s1  = " f000(){return \"Qa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WI" ascii
    $s2  = "tion f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s3  = " \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Wb\";})(),(func" ascii
    $s4  = "\"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s5  = "){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Wb\";})()" ascii
    $s6  = "j\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s7  = ",(function f000(){return \"Wb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s8  = "00(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s9  = "tion f000(){return \"Qz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s10 = "n\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function " ascii
    $s11 = "urn \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s12 = "{return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(" ascii
    $s13 = "turn \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s14 = " f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc" ascii
    $s15 = "urn \"ZFe\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s16 = "n f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s17 = "function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"UEg\";})(),(function f000(){r" ascii
    $s18 = "nction f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(function f000(){retu" ascii
    $s19 = "on f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return " ascii
    $s20 = "(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
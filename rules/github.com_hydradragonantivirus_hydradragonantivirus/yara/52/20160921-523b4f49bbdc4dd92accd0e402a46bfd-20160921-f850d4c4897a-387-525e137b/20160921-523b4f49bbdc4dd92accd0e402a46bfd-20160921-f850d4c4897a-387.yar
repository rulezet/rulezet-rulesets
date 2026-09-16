rule _20160921_523b4f49bbdc4dd92accd0e402a46bfd_20160921_f850d4c4897a_387 {
  meta:
    description = "datamaliciousorder - from files 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash2       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1  = "function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){re" ascii
    $s2  = "n\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function" ascii
    $s3  = "\"BQb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s4  = "000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj" ascii
    $s5  = "n f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s6  = "ction f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){retu" ascii
    $s7  = "){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";}" ascii
    $s8  = "(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s9  = " \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s10 = "){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"GGn\";" ascii
    $s11 = "rn \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(" ascii
    $s12 = "{return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})" ascii
    $s13 = ";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Rh\";})(),(function f0" ascii
    $s14 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(fu" ascii
    $s15 = "00(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn" ascii
    $s16 = "u\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function" ascii
    $s17 = "GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s18 = "return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})()," ascii
    $s19 = "f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GG" ascii
    $s20 = "GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_72 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"

  strings:
    $s1  = "(function f000(){return \"Fs\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s2  = " \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s3  = "ction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){retu" ascii
    $s4  = "\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function" ascii
    $s5  = "turn \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(" ascii
    $s6  = "turn \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s7  = "on f000(){return \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s8  = "return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})()" ascii
    $s9  = "n \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fu" ascii
    $s10 = "n \"Do\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s11 = "n \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s12 = "),(function f000(){return \"Um\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s13 = "urn \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(f" ascii
    $s14 = "q\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s15 = "urn \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(" ascii
    $s16 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s17 = "return \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s18 = ";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s19 = "(){return \"KDh\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\"" ascii
    $s20 = "rn \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
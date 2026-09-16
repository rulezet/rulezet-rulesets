rule _20160921_bcf3911462135150c96c6b8eccf51628_20160921_f7b964e1d5b6_3133 {
  meta:
    description = "datamaliciousorder - from files 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1 = "nction f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s2 = "nction f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s3 = "tion f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s4 = ",(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s5 = " \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(funct" ascii
    $s6 = "on f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s7 = "{return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_3e5e21af311d_1649 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_a2977e58d35241f07c3f294ca2097899.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash3       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"

  strings:
    $s1  = "(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";" ascii
    $s2  = "\"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(funct" ascii
    $s3  = "urn \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4  = "0(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";" ascii
    $s5  = "{return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})" ascii
    $s6  = "nction f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s7  = "nction f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii
    $s8  = "i\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function" ascii
    $s9  = "ction f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return" ascii
    $s10 = "(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";" ascii
    $s11 = "f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
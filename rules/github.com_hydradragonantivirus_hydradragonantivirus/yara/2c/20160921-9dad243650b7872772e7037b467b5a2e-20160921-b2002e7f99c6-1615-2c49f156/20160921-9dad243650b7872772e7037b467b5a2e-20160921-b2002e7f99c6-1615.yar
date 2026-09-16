rule _20160921_9dad243650b7872772e7037b467b5a2e_20160921_b2002e7f99c6_1615 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"

  strings:
    $s1  = "tion f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s2  = "unction f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii
    $s3  = "000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\"" ascii
    $s4  = "Ti\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s5  = "000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\"" ascii
    $s6  = "n \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"PTi\";})(),(fu" ascii
    $s7  = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"HJm\";})(),(function f000(){" ascii
    $s8  = "q\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f" ascii
    $s9  = "unction f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s10 = "(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";" ascii
    $s11 = "n f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"G" ascii
    $s12 = ";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
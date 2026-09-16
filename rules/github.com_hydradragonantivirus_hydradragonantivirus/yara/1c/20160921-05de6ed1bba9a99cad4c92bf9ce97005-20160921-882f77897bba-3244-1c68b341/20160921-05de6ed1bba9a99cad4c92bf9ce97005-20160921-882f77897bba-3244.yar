rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_882f77897bba_3244 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_882f77897bba85afdc56810c29ef4cbb.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"
    hash3       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash4       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash5       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1 = "return \"ZIi\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})()" ascii
    $s2 = "j\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s3 = "function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii
    $s4 = "nction f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){ret" ascii
    $s5 = "unction f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MMz\";})(),(function f000(){retu" ascii
    $s6 = "eturn \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
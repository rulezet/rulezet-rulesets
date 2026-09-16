rule _20160921_3bce2f31e98c152d025886ed17309773_20160921_8ac006dedc62_4992 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"

  strings:
    $s1 = "urn \"Wh\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(f" ascii
    $s2 = "return \"WIj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})" ascii
    $s3 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Nx\";})(),(function f000(){re" ascii
    $s4 = "TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(functi" ascii
    $s5 = "n \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
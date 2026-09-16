rule _20160921_37b52e41aabc93218d864c1665a33610_20160922_9d6af2734812_4923 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "0(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";" ascii
    $s2 = "Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function" ascii
    $s3 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s4 = "tion f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s5 = "nction f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
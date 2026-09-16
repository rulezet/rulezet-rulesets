rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_4b801afbcd98_4922 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_4b801afbcd9818be02d65ee0ac30ad19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"

  strings:
    $s1 = "{return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(" ascii
    $s2 = "(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s3 = "return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(" ascii
    $s4 = "j\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Iq\";})(),(function " ascii
    $s5 = "(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
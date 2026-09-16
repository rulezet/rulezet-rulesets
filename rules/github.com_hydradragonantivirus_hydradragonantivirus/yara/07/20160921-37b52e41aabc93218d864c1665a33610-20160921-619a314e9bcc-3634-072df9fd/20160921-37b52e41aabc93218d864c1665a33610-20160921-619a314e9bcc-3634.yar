rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_619a314e9bcc_3634 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_619a314e9bcca286c046dff250b54b6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"

  strings:
    $s1 = "})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s2 = "tion f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s3 = "\"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s4 = "{return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(" ascii
    $s5 = "n\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"SGs\";})(),(function" ascii
    $s6 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
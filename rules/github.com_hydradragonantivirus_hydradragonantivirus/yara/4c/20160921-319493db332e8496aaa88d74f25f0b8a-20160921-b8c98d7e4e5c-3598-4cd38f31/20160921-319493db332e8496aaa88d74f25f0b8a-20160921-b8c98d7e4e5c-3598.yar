rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_b8c98d7e4e5c_3598 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"

  strings:
    $s1 = ")(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(fun" ascii
    $s3 = "urn \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s4 = " \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(func" ascii
    $s5 = "(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";}" ascii
    $s6 = "00(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
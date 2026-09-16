rule _20160921_66566a9bbc7830091a244fa6674b709b_20160921_e2594cbf7523_3865 {
  meta:
    description = "datamaliciousorder - from files 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash2       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash3       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = "eturn \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})()," ascii
    $s2 = "nction f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){retu" ascii
    $s3 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return" ascii
    $s4 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii
    $s5 = ";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f00" ascii
    $s6 = "\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
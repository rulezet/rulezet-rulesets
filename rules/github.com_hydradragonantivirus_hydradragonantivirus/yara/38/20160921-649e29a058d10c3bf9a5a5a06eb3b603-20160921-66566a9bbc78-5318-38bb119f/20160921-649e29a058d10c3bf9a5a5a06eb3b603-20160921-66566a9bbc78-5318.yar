rule _20160921_649e29a058d10c3bf9a5a5a06eb3b603_20160921_66566a9bbc78_5318 {
  meta:
    description = "datamaliciousorder - from files 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash2       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash3       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash4       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash5       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash6       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1 = "(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){r" ascii
    $s2 = "urn \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(f" ascii
    $s3 = "\"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s4 = "ion f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
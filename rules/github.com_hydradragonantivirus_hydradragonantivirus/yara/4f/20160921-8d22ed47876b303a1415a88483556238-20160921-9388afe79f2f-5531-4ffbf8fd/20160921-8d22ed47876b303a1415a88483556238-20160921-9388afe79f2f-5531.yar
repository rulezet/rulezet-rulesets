rule _20160921_8d22ed47876b303a1415a88483556238_20160921_9388afe79f2f_5531 {
  meta:
    description = "datamaliciousorder - from files 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash2       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash3       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1 = "00(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa" ascii
    $s2 = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";}" ascii
    $s3 = "function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Wy\";})(),(function f000(){re" ascii
    $s4 = "0(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TKl\";" ascii
    $s5 = "Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
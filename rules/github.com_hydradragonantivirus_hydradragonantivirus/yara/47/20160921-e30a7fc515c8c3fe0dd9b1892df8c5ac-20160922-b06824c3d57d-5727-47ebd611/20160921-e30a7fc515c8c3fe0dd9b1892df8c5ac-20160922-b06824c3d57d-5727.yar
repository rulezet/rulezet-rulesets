rule _20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac_20160922_b06824c3d57d_5727 {
  meta:
    description = "datamaliciousorder - from files 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash2       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash3       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1 = "return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})()" ascii
    $s2 = "urn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(" ascii
    $s3 = ")(),(function f000(){return \"PTs\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})(),(function f00" ascii
    $s4 = "tion f000(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s5 = "turn \"QDg\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SGs\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
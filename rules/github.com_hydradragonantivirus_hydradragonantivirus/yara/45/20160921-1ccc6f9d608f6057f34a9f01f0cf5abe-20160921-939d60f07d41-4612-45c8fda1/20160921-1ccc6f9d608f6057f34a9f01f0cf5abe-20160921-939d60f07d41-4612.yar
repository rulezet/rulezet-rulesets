rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_939d60f07d41_4612 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash3       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1 = "eturn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Qj\";})()" ascii
    $s2 = ";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f0" ascii
    $s3 = "rn \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(f" ascii
    $s4 = "f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj" ascii
    $s5 = "on f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
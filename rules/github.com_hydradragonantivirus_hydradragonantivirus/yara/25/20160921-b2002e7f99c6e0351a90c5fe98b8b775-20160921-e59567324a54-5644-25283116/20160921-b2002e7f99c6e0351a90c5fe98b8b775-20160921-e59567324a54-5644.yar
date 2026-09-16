rule _20160921_b2002e7f99c6e0351a90c5fe98b8b775_20160921_e59567324a54_5644 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "0(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";}" ascii
    $s2 = "ion f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return " ascii
    $s3 = "eturn \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()" ascii
    $s4 = "turn \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()" ascii
    $s5 = " f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
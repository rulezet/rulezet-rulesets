rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_e30a7fc515c8_5048 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"

  strings:
    $s1 = "),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii
    $s2 = "turn \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Lo\";})()," ascii
    $s3 = ")(),(function f000(){return \"BIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s4 = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(" ascii
    $s5 = "ction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
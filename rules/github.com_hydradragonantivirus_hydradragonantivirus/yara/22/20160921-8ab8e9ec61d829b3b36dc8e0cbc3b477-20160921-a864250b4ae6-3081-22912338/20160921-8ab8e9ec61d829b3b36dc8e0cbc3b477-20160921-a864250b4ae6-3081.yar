rule _20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477_20160921_a864250b4ae6_3081 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash2       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"

  strings:
    $s1 = "nction f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s2 = "){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";}" ascii
    $s3 = "Mz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(functio" ascii
    $s4 = "ction f000(){return \"MKa\";})()];" fullword ascii
    $s5 = "ction f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s6 = "turn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s7 = ";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
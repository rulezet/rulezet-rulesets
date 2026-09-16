rule _20160921_68e1fc90afca497654d8f771197c2097_20160921_be882ab89423_5343 {
  meta:
    description = "datamaliciousorder - from files 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash2       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"

  strings:
    $s1 = "(function f000(){return \"Oe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){re" ascii
    $s2 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Sq\";})(),(function f00" ascii
    $s3 = "n \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s4 = "urn \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(" ascii
    $s5 = "on f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
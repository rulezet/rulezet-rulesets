rule _20160921_86391eeb92939f7926213db5cee16e4d_20160921_c459056d51b1_5480 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1 = "f000(){return \"Br\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Br" ascii
    $s2 = " f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"D" ascii
    $s3 = "urn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s4 = "eturn \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()" ascii
    $s5 = "rn \"MJq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
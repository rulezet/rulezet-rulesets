rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_b04df6930d82_4709 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"

  strings:
    $s1 = ",(function f000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s2 = "000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DY" ascii
    $s3 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){r" ascii
    $s4 = "f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s5 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
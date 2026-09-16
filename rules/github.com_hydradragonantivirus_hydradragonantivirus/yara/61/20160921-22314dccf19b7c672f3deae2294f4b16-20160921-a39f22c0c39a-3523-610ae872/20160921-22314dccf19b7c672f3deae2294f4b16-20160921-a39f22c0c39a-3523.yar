rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_a39f22c0c39a_3523 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1 = "turn \"DNa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s2 = " f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn" ascii
    $s3 = "function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s4 = "{return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})()" ascii
    $s5 = "c\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s6 = "f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
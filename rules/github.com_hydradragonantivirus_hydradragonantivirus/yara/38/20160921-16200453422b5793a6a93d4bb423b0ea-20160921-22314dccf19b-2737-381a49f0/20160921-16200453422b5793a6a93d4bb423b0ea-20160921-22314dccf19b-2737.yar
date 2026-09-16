rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_22314dccf19b_2737 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"

  strings:
    $s1 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){" ascii
    $s2 = "nction f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s3 = " \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4 = " \"Yz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(func" ascii
    $s5 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"ZIi" ascii
    $s6 = "n f000(){return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GG" ascii
    $s7 = "})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
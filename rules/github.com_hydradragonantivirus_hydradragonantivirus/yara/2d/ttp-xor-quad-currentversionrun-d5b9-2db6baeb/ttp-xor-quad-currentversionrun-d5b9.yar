rule TTP_XOR_QUAD_CurrentVersionRun_d5b9 {
  strings:
    $key_d5b9 = { 86 d6 [2] a2 d8 [2] 89 f4 [2] a7 d6 [2] b3 cd [2] bc d7 [2] a2 ca [2] a0 cb [2] bb cd [2] a7 ca [2] bb e5 }

  condition:
    any of them
}
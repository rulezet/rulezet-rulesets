rule TTP_XOR_QUAD_CurrentVersionRun_d2b7 {
  strings:
    $key_d2b7 = { 81 d8 [2] a5 d6 [2] 8e fa [2] a0 d8 [2] b4 c3 [2] bb d9 [2] a5 c4 [2] a7 c5 [2] bc c3 [2] a0 c4 [2] bc eb }

  condition:
    any of them
}
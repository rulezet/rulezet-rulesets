rule TTP_XOR_QUAD_CurrentVersionRun_c7b3 {
  strings:
    $key_c7b3 = { 94 dc [2] b0 d2 [2] 9b fe [2] b5 dc [2] a1 c7 [2] ae dd [2] b0 c0 [2] b2 c1 [2] a9 c7 [2] b5 c0 [2] a9 ef }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_c1b3 {
  strings:
    $key_c1b3 = { 92 dc [2] b6 d2 [2] 9d fe [2] b3 dc [2] a7 c7 [2] a8 dd [2] b6 c0 [2] b4 c1 [2] af c7 [2] b3 c0 [2] af ef }

  condition:
    any of them
}
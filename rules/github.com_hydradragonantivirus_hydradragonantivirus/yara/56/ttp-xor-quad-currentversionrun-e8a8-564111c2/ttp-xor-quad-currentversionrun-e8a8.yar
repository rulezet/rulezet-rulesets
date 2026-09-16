rule TTP_XOR_QUAD_CurrentVersionRun_e8a8 {
  strings:
    $key_e8a8 = { bb c7 [2] 9f c9 [2] b4 e5 [2] 9a c7 [2] 8e dc [2] 81 c6 [2] 9f db [2] 9d da [2] 86 dc [2] 9a db [2] 86 f4 }

  condition:
    any of them
}
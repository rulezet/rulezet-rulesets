rule TTP_XOR_QUAD_CurrentVersionRun_e7a6 {
  strings:
    $key_e7a6 = { b4 c9 [2] 90 c7 [2] bb eb [2] 95 c9 [2] 81 d2 [2] 8e c8 [2] 90 d5 [2] 92 d4 [2] 89 d2 [2] 95 d5 [2] 89 fa }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_e746 {
  strings:
    $key_e746 = { b4 29 [2] 90 27 [2] bb 0b [2] 95 29 [2] 81 32 [2] 8e 28 [2] 90 35 [2] 92 34 [2] 89 32 [2] 95 35 [2] 89 1a }

  condition:
    any of them
}
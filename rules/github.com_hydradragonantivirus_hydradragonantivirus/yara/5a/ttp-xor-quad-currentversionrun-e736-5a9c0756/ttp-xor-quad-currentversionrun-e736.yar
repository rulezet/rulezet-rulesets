rule TTP_XOR_QUAD_CurrentVersionRun_e736 {
  strings:
    $key_e736 = { b4 59 [2] 90 57 [2] bb 7b [2] 95 59 [2] 81 42 [2] 8e 58 [2] 90 45 [2] 92 44 [2] 89 42 [2] 95 45 [2] 89 6a }

  condition:
    any of them
}
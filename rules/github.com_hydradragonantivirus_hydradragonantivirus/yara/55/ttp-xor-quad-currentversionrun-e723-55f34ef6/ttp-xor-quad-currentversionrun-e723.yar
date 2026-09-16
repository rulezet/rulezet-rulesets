rule TTP_XOR_QUAD_CurrentVersionRun_e723 {
  strings:
    $key_e723 = { b4 4c [2] 90 42 [2] bb 6e [2] 95 4c [2] 81 57 [2] 8e 4d [2] 90 50 [2] 92 51 [2] 89 57 [2] 95 50 [2] 89 7f }

  condition:
    any of them
}
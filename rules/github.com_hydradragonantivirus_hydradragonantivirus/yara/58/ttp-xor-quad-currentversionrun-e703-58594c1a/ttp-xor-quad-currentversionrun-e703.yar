rule TTP_XOR_QUAD_CurrentVersionRun_e703 {
  strings:
    $key_e703 = { b4 6c [2] 90 62 [2] bb 4e [2] 95 6c [2] 81 77 [2] 8e 6d [2] 90 70 [2] 92 71 [2] 89 77 [2] 95 70 [2] 89 5f }

  condition:
    any of them
}
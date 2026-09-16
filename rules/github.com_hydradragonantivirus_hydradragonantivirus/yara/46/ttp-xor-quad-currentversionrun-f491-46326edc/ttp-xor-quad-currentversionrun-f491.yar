rule TTP_XOR_QUAD_CurrentVersionRun_f491 {
  strings:
    $key_f491 = { a7 fe [2] 83 f0 [2] a8 dc [2] 86 fe [2] 92 e5 [2] 9d ff [2] 83 e2 [2] 81 e3 [2] 9a e5 [2] 86 e2 [2] 9a cd }

  condition:
    any of them
}
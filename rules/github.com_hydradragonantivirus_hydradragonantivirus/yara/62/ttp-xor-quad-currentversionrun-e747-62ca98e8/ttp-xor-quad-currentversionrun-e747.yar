rule TTP_XOR_QUAD_CurrentVersionRun_e747 {
  strings:
    $key_e747 = { b4 28 [2] 90 26 [2] bb 0a [2] 95 28 [2] 81 33 [2] 8e 29 [2] 90 34 [2] 92 35 [2] 89 33 [2] 95 34 [2] 89 1b }

  condition:
    any of them
}
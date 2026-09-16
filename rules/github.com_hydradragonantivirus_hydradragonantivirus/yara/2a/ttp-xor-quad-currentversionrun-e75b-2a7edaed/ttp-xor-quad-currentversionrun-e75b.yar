rule TTP_XOR_QUAD_CurrentVersionRun_e75b {
  strings:
    $key_e75b = { b4 34 [2] 90 3a [2] bb 16 [2] 95 34 [2] 81 2f [2] 8e 35 [2] 90 28 [2] 92 29 [2] 89 2f [2] 95 28 [2] 89 07 }

  condition:
    any of them
}
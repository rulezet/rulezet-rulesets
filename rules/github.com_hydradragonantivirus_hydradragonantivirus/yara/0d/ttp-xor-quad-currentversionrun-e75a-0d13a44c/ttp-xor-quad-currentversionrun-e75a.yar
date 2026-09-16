rule TTP_XOR_QUAD_CurrentVersionRun_e75a {
  strings:
    $key_e75a = { b4 35 [2] 90 3b [2] bb 17 [2] 95 35 [2] 81 2e [2] 8e 34 [2] 90 29 [2] 92 28 [2] 89 2e [2] 95 29 [2] 89 06 }

  condition:
    any of them
}
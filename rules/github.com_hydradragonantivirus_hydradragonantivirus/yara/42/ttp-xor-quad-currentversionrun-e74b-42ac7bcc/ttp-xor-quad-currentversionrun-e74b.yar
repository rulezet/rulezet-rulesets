rule TTP_XOR_QUAD_CurrentVersionRun_e74b {
  strings:
    $key_e74b = { b4 24 [2] 90 2a [2] bb 06 [2] 95 24 [2] 81 3f [2] 8e 25 [2] 90 38 [2] 92 39 [2] 89 3f [2] 95 38 [2] 89 17 }

  condition:
    any of them
}
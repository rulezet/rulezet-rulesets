rule TTP_XOR_QUAD_CurrentVersionRun_e755 {
  strings:
    $key_e755 = { b4 3a [2] 90 34 [2] bb 18 [2] 95 3a [2] 81 21 [2] 8e 3b [2] 90 26 [2] 92 27 [2] 89 21 [2] 95 26 [2] 89 09 }

  condition:
    any of them
}
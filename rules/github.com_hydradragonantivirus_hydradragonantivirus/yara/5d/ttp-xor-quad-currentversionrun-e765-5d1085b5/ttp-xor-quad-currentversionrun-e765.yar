rule TTP_XOR_QUAD_CurrentVersionRun_e765 {
  strings:
    $key_e765 = { b4 0a [2] 90 04 [2] bb 28 [2] 95 0a [2] 81 11 [2] 8e 0b [2] 90 16 [2] 92 17 [2] 89 11 [2] 95 16 [2] 89 39 }

  condition:
    any of them
}
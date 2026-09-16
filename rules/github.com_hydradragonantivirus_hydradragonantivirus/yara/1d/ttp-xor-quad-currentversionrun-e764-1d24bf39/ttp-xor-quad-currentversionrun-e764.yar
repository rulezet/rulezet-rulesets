rule TTP_XOR_QUAD_CurrentVersionRun_e764 {
  strings:
    $key_e764 = { b4 0b [2] 90 05 [2] bb 29 [2] 95 0b [2] 81 10 [2] 8e 0a [2] 90 17 [2] 92 16 [2] 89 10 [2] 95 17 [2] 89 38 }

  condition:
    any of them
}
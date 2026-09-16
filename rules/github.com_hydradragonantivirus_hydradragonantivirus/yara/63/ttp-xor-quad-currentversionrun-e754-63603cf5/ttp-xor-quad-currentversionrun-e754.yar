rule TTP_XOR_QUAD_CurrentVersionRun_e754 {
  strings:
    $key_e754 = { b4 3b [2] 90 35 [2] bb 19 [2] 95 3b [2] 81 20 [2] 8e 3a [2] 90 27 [2] 92 26 [2] 89 20 [2] 95 27 [2] 89 08 }

  condition:
    any of them
}
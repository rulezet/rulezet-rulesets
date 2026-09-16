rule TTP_XOR_QUAD_CurrentVersionRun_e777 {
  strings:
    $key_e777 = { b4 18 [2] 90 16 [2] bb 3a [2] 95 18 [2] 81 03 [2] 8e 19 [2] 90 04 [2] 92 05 [2] 89 03 [2] 95 04 [2] 89 2b }

  condition:
    any of them
}
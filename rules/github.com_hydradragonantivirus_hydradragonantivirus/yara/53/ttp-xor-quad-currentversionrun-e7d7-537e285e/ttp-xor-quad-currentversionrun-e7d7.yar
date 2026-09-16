rule TTP_XOR_QUAD_CurrentVersionRun_e7d7 {
  strings:
    $key_e7d7 = { b4 b8 [2] 90 b6 [2] bb 9a [2] 95 b8 [2] 81 a3 [2] 8e b9 [2] 90 a4 [2] 92 a5 [2] 89 a3 [2] 95 a4 [2] 89 8b }

  condition:
    any of them
}
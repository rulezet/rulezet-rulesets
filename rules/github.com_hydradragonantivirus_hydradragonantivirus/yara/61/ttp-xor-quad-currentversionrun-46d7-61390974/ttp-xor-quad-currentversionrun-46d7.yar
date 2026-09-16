rule TTP_XOR_QUAD_CurrentVersionRun_46d7 {
  strings:
    $key_46d7 = { 15 b8 [2] 31 b6 [2] 1a 9a [2] 34 b8 [2] 20 a3 [2] 2f b9 [2] 31 a4 [2] 33 a5 [2] 28 a3 [2] 34 a4 [2] 28 8b }

  condition:
    any of them
}
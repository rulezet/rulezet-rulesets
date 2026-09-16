rule TTP_XOR_QUAD_CurrentVersionRun_36d7 {
  strings:
    $key_36d7 = { 65 b8 [2] 41 b6 [2] 6a 9a [2] 44 b8 [2] 50 a3 [2] 5f b9 [2] 41 a4 [2] 43 a5 [2] 58 a3 [2] 44 a4 [2] 58 8b }

  condition:
    any of them
}
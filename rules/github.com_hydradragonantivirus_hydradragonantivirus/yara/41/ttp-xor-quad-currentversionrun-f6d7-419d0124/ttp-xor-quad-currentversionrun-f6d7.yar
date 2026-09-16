rule TTP_XOR_QUAD_CurrentVersionRun_f6d7 {
  strings:
    $key_f6d7 = { a5 b8 [2] 81 b6 [2] aa 9a [2] 84 b8 [2] 90 a3 [2] 9f b9 [2] 81 a4 [2] 83 a5 [2] 98 a3 [2] 84 a4 [2] 98 8b }

  condition:
    any of them
}
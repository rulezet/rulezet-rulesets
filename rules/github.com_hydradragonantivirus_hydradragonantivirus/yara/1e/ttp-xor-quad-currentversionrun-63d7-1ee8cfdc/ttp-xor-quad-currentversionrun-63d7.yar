rule TTP_XOR_QUAD_CurrentVersionRun_63d7 {
  strings:
    $key_63d7 = { 30 b8 [2] 14 b6 [2] 3f 9a [2] 11 b8 [2] 05 a3 [2] 0a b9 [2] 14 a4 [2] 16 a5 [2] 0d a3 [2] 11 a4 [2] 0d 8b }

  condition:
    any of them
}
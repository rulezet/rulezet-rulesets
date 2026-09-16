rule TTP_XOR_QUAD_CurrentVersionRun_6ad7 {
  strings:
    $key_6ad7 = { 39 b8 [2] 1d b6 [2] 36 9a [2] 18 b8 [2] 0c a3 [2] 03 b9 [2] 1d a4 [2] 1f a5 [2] 04 a3 [2] 18 a4 [2] 04 8b }

  condition:
    any of them
}
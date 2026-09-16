rule TTP_XOR_QUAD_CurrentVersionRun_5ad7 {
  strings:
    $key_5ad7 = { 09 b8 [2] 2d b6 [2] 06 9a [2] 28 b8 [2] 3c a3 [2] 33 b9 [2] 2d a4 [2] 2f a5 [2] 34 a3 [2] 28 a4 [2] 34 8b }

  condition:
    any of them
}
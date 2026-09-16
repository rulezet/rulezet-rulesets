rule TTP_XOR_QUAD_CurrentVersionRun_5ad6 {
  strings:
    $key_5ad6 = { 09 b9 [2] 2d b7 [2] 06 9b [2] 28 b9 [2] 3c a2 [2] 33 b8 [2] 2d a5 [2] 2f a4 [2] 34 a2 [2] 28 a5 [2] 34 8a }

  condition:
    any of them
}
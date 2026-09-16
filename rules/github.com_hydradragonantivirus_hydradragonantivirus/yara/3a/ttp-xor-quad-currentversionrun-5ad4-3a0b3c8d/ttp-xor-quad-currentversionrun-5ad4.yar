rule TTP_XOR_QUAD_CurrentVersionRun_5ad4 {
  strings:
    $key_5ad4 = { 09 bb [2] 2d b5 [2] 06 99 [2] 28 bb [2] 3c a0 [2] 33 ba [2] 2d a7 [2] 2f a6 [2] 34 a0 [2] 28 a7 [2] 34 88 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_5ad1 {
  strings:
    $key_5ad1 = { 09 be [2] 2d b0 [2] 06 9c [2] 28 be [2] 3c a5 [2] 33 bf [2] 2d a2 [2] 2f a3 [2] 34 a5 [2] 28 a2 [2] 34 8d }

  condition:
    any of them
}
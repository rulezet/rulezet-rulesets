rule TTP_XOR_QUAD_CurrentVersionRun_41d1 {
  strings:
    $key_41d1 = { 12 be [2] 36 b0 [2] 1d 9c [2] 33 be [2] 27 a5 [2] 28 bf [2] 36 a2 [2] 34 a3 [2] 2f a5 [2] 33 a2 [2] 2f 8d }

  condition:
    any of them
}
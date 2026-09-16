rule TTP_XOR_QUAD_CurrentVersionRun_4ad1 {
  strings:
    $key_4ad1 = { 19 be [2] 3d b0 [2] 16 9c [2] 38 be [2] 2c a5 [2] 23 bf [2] 3d a2 [2] 3f a3 [2] 24 a5 [2] 38 a2 [2] 24 8d }

  condition:
    any of them
}
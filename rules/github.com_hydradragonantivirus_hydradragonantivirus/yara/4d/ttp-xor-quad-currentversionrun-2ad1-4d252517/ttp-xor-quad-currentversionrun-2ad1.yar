rule TTP_XOR_QUAD_CurrentVersionRun_2ad1 {
  strings:
    $key_2ad1 = { 79 be [2] 5d b0 [2] 76 9c [2] 58 be [2] 4c a5 [2] 43 bf [2] 5d a2 [2] 5f a3 [2] 44 a5 [2] 58 a2 [2] 44 8d }

  condition:
    any of them
}
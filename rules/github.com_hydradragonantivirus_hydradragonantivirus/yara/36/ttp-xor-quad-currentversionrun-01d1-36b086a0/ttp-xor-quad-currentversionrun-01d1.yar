rule TTP_XOR_QUAD_CurrentVersionRun_01d1 {
  strings:
    $key_01d1 = { 52 be [2] 76 b0 [2] 5d 9c [2] 73 be [2] 67 a5 [2] 68 bf [2] 76 a2 [2] 74 a3 [2] 6f a5 [2] 73 a2 [2] 6f 8d }

  condition:
    any of them
}
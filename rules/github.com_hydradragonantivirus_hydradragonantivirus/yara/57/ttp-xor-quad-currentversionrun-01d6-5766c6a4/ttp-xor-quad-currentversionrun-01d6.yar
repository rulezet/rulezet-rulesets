rule TTP_XOR_QUAD_CurrentVersionRun_01d6 {
  strings:
    $key_01d6 = { 52 b9 [2] 76 b7 [2] 5d 9b [2] 73 b9 [2] 67 a2 [2] 68 b8 [2] 76 a5 [2] 74 a4 [2] 6f a2 [2] 73 a5 [2] 6f 8a }

  condition:
    any of them
}
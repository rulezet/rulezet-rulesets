rule TTP_XOR_QUAD_CurrentVersionRun_1ad6 {
  strings:
    $key_1ad6 = { 49 b9 [2] 6d b7 [2] 46 9b [2] 68 b9 [2] 7c a2 [2] 73 b8 [2] 6d a5 [2] 6f a4 [2] 74 a2 [2] 68 a5 [2] 74 8a }

  condition:
    any of them
}
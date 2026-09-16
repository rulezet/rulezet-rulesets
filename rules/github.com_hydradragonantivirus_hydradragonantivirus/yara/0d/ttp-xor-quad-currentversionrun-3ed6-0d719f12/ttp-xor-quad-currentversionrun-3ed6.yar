rule TTP_XOR_QUAD_CurrentVersionRun_3ed6 {
  strings:
    $key_3ed6 = { 6d b9 [2] 49 b7 [2] 62 9b [2] 4c b9 [2] 58 a2 [2] 57 b8 [2] 49 a5 [2] 4b a4 [2] 50 a2 [2] 4c a5 [2] 50 8a }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0ed6 {
  strings:
    $key_0ed6 = { 5d b9 [2] 79 b7 [2] 52 9b [2] 7c b9 [2] 68 a2 [2] 67 b8 [2] 79 a5 [2] 7b a4 [2] 60 a2 [2] 7c a5 [2] 60 8a }

  condition:
    any of them
}
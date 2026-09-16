rule TTP_XOR_QUAD_CurrentVersionRun_1ac6 {
  strings:
    $key_1ac6 = { 49 a9 [2] 6d a7 [2] 46 8b [2] 68 a9 [2] 7c b2 [2] 73 a8 [2] 6d b5 [2] 6f b4 [2] 74 b2 [2] 68 b5 [2] 74 9a }

  condition:
    any of them
}
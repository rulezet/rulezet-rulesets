rule TTP_XOR_QUAD_CurrentVersionRun_39c6 {
  strings:
    $key_39c6 = { 6a a9 [2] 4e a7 [2] 65 8b [2] 4b a9 [2] 5f b2 [2] 50 a8 [2] 4e b5 [2] 4c b4 [2] 57 b2 [2] 4b b5 [2] 57 9a }

  condition:
    any of them
}
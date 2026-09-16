rule TTP_XOR_QUAD_CurrentVersionRun_0bc6 {
  strings:
    $key_0bc6 = { 58 a9 [2] 7c a7 [2] 57 8b [2] 79 a9 [2] 6d b2 [2] 62 a8 [2] 7c b5 [2] 7e b4 [2] 65 b2 [2] 79 b5 [2] 65 9a }

  condition:
    any of them
}
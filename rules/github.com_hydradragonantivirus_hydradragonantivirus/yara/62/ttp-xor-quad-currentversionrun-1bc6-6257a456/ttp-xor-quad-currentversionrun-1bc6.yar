rule TTP_XOR_QUAD_CurrentVersionRun_1bc6 {
  strings:
    $key_1bc6 = { 48 a9 [2] 6c a7 [2] 47 8b [2] 69 a9 [2] 7d b2 [2] 72 a8 [2] 6c b5 [2] 6e b4 [2] 75 b2 [2] 69 b5 [2] 75 9a }

  condition:
    any of them
}
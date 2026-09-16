rule TTP_XOR_QUAD_CurrentVersionRun_1bd6 {
  strings:
    $key_1bd6 = { 48 b9 [2] 6c b7 [2] 47 9b [2] 69 b9 [2] 7d a2 [2] 72 b8 [2] 6c a5 [2] 6e a4 [2] 75 a2 [2] 69 a5 [2] 75 8a }

  condition:
    any of them
}
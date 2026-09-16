rule TTP_XOR_QUAD_CurrentVersionRun_4ec6 {
  strings:
    $key_4ec6 = { 1d a9 [2] 39 a7 [2] 12 8b [2] 3c a9 [2] 28 b2 [2] 27 a8 [2] 39 b5 [2] 3b b4 [2] 20 b2 [2] 3c b5 [2] 20 9a }

  condition:
    any of them
}
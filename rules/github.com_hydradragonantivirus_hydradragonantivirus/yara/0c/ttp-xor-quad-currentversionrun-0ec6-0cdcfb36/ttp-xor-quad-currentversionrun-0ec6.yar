rule TTP_XOR_QUAD_CurrentVersionRun_0ec6 {
  strings:
    $key_0ec6 = { 5d a9 [2] 79 a7 [2] 52 8b [2] 7c a9 [2] 68 b2 [2] 67 a8 [2] 79 b5 [2] 7b b4 [2] 60 b2 [2] 7c b5 [2] 60 9a }

  condition:
    any of them
}
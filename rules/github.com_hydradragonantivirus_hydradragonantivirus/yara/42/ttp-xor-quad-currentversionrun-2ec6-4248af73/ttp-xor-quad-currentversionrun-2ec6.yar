rule TTP_XOR_QUAD_CurrentVersionRun_2ec6 {
  strings:
    $key_2ec6 = { 7d a9 [2] 59 a7 [2] 72 8b [2] 5c a9 [2] 48 b2 [2] 47 a8 [2] 59 b5 [2] 5b b4 [2] 40 b2 [2] 5c b5 [2] 40 9a }

  condition:
    any of them
}
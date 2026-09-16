rule TTP_XOR_QUAD_CurrentVersionRun_7ec6 {
  strings:
    $key_7ec6 = { 2d a9 [2] 09 a7 [2] 22 8b [2] 0c a9 [2] 18 b2 [2] 17 a8 [2] 09 b5 [2] 0b b4 [2] 10 b2 [2] 0c b5 [2] 10 9a }

  condition:
    any of them
}
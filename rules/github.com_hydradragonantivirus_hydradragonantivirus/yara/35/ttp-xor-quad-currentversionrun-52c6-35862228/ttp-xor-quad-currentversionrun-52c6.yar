rule TTP_XOR_QUAD_CurrentVersionRun_52c6 {
  strings:
    $key_52c6 = { 01 a9 [2] 25 a7 [2] 0e 8b [2] 20 a9 [2] 34 b2 [2] 3b a8 [2] 25 b5 [2] 27 b4 [2] 3c b2 [2] 20 b5 [2] 3c 9a }

  condition:
    any of them
}
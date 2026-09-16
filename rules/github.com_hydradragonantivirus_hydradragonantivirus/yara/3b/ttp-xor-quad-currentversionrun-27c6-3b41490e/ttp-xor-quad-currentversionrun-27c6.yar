rule TTP_XOR_QUAD_CurrentVersionRun_27c6 {
  strings:
    $key_27c6 = { 74 a9 [2] 50 a7 [2] 7b 8b [2] 55 a9 [2] 41 b2 [2] 4e a8 [2] 50 b5 [2] 52 b4 [2] 49 b2 [2] 55 b5 [2] 49 9a }

  condition:
    any of them
}
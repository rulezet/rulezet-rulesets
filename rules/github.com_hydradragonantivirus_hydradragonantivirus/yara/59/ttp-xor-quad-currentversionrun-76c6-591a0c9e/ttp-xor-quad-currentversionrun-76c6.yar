rule TTP_XOR_QUAD_CurrentVersionRun_76c6 {
  strings:
    $key_76c6 = { 25 a9 [2] 01 a7 [2] 2a 8b [2] 04 a9 [2] 10 b2 [2] 1f a8 [2] 01 b5 [2] 03 b4 [2] 18 b2 [2] 04 b5 [2] 18 9a }

  condition:
    any of them
}
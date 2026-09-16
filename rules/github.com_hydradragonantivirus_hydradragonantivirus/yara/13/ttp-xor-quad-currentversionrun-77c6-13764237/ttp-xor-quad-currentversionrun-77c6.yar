rule TTP_XOR_QUAD_CurrentVersionRun_77c6 {
  strings:
    $key_77c6 = { 24 a9 [2] 00 a7 [2] 2b 8b [2] 05 a9 [2] 11 b2 [2] 1e a8 [2] 00 b5 [2] 02 b4 [2] 19 b2 [2] 05 b5 [2] 19 9a }

  condition:
    any of them
}
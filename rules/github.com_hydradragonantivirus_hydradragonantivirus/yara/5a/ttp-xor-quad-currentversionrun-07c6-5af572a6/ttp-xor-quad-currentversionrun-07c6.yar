rule TTP_XOR_QUAD_CurrentVersionRun_07c6 {
  strings:
    $key_07c6 = { 54 a9 [2] 70 a7 [2] 5b 8b [2] 75 a9 [2] 61 b2 [2] 6e a8 [2] 70 b5 [2] 72 b4 [2] 69 b2 [2] 75 b5 [2] 69 9a }

  condition:
    any of them
}
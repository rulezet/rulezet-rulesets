rule TTP_XOR_QUAD_CurrentVersionRun_52d6 {
  strings:
    $key_52d6 = { 01 b9 [2] 25 b7 [2] 0e 9b [2] 20 b9 [2] 34 a2 [2] 3b b8 [2] 25 a5 [2] 27 a4 [2] 3c a2 [2] 20 a5 [2] 3c 8a }

  condition:
    any of them
}
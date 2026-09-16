rule TTP_XOR_QUAD_CurrentVersionRun_02d6 {
  strings:
    $key_02d6 = { 51 b9 [2] 75 b7 [2] 5e 9b [2] 70 b9 [2] 64 a2 [2] 6b b8 [2] 75 a5 [2] 77 a4 [2] 6c a2 [2] 70 a5 [2] 6c 8a }

  condition:
    any of them
}
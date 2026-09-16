rule TTP_XOR_QUAD_CurrentVersionRun_22d6 {
  strings:
    $key_22d6 = { 71 b9 [2] 55 b7 [2] 7e 9b [2] 50 b9 [2] 44 a2 [2] 4b b8 [2] 55 a5 [2] 57 a4 [2] 4c a2 [2] 50 a5 [2] 4c 8a }

  condition:
    any of them
}
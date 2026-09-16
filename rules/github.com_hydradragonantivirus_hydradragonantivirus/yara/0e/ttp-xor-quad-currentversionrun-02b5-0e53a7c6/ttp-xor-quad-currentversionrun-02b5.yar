rule TTP_XOR_QUAD_CurrentVersionRun_02b5 {
  strings:
    $key_02b5 = { 51 da [2] 75 d4 [2] 5e f8 [2] 70 da [2] 64 c1 [2] 6b db [2] 75 c6 [2] 77 c7 [2] 6c c1 [2] 70 c6 [2] 6c e9 }

  condition:
    any of them
}
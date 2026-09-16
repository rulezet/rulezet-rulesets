rule TTP_XOR_QUAD_CurrentVersionRun_f2b5 {
  strings:
    $key_f2b5 = { a1 da [2] 85 d4 [2] ae f8 [2] 80 da [2] 94 c1 [2] 9b db [2] 85 c6 [2] 87 c7 [2] 9c c1 [2] 80 c6 [2] 9c e9 }

  condition:
    any of them
}
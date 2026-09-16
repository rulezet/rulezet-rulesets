rule TTP_XOR_QUAD_CurrentVersionRun_f2b4 {
  strings:
    $key_f2b4 = { a1 db [2] 85 d5 [2] ae f9 [2] 80 db [2] 94 c0 [2] 9b da [2] 85 c7 [2] 87 c6 [2] 9c c0 [2] 80 c7 [2] 9c e8 }

  condition:
    any of them
}
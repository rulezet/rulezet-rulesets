rule TTP_XOR_QUAD_CurrentVersionRun_02b4 {
  strings:
    $key_02b4 = { 51 db [2] 75 d5 [2] 5e f9 [2] 70 db [2] 64 c0 [2] 6b da [2] 75 c7 [2] 77 c6 [2] 6c c0 [2] 70 c7 [2] 6c e8 }

  condition:
    any of them
}
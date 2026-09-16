rule TTP_XOR_QUAD_CurrentVersionRun_52b4 {
  strings:
    $key_52b4 = { 01 db [2] 25 d5 [2] 0e f9 [2] 20 db [2] 34 c0 [2] 3b da [2] 25 c7 [2] 27 c6 [2] 3c c0 [2] 20 c7 [2] 3c e8 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_32b4 {
  strings:
    $key_32b4 = { 61 db [2] 45 d5 [2] 6e f9 [2] 40 db [2] 54 c0 [2] 5b da [2] 45 c7 [2] 47 c6 [2] 5c c0 [2] 40 c7 [2] 5c e8 }

  condition:
    any of them
}
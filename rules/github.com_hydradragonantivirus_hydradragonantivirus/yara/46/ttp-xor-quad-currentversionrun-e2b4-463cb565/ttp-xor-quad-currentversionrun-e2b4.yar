rule TTP_XOR_QUAD_CurrentVersionRun_e2b4 {
  strings:
    $key_e2b4 = { b1 db [2] 95 d5 [2] be f9 [2] 90 db [2] 84 c0 [2] 8b da [2] 95 c7 [2] 97 c6 [2] 8c c0 [2] 90 c7 [2] 8c e8 }

  condition:
    any of them
}
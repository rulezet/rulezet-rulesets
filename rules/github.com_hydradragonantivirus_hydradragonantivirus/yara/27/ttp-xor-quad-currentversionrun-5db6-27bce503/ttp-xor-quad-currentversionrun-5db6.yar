rule TTP_XOR_QUAD_CurrentVersionRun_5db6 {
  strings:
    $key_5db6 = { 0e d9 [2] 2a d7 [2] 01 fb [2] 2f d9 [2] 3b c2 [2] 34 d8 [2] 2a c5 [2] 28 c4 [2] 33 c2 [2] 2f c5 [2] 33 ea }

  condition:
    any of them
}
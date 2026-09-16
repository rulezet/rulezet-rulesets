rule TTP_XOR_QUAD_CurrentVersionRun_2db6 {
  strings:
    $key_2db6 = { 7e d9 [2] 5a d7 [2] 71 fb [2] 5f d9 [2] 4b c2 [2] 44 d8 [2] 5a c5 [2] 58 c4 [2] 43 c2 [2] 5f c5 [2] 43 ea }

  condition:
    any of them
}
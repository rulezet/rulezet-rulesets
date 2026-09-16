rule TTP_XOR_QUAD_CurrentVersionRun_1db6 {
  strings:
    $key_1db6 = { 4e d9 [2] 6a d7 [2] 41 fb [2] 6f d9 [2] 7b c2 [2] 74 d8 [2] 6a c5 [2] 68 c4 [2] 73 c2 [2] 6f c5 [2] 73 ea }

  condition:
    any of them
}
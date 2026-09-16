rule TTP_XOR_QUAD_CurrentVersionRun_58b6 {
  strings:
    $key_58b6 = { 0b d9 [2] 2f d7 [2] 04 fb [2] 2a d9 [2] 3e c2 [2] 31 d8 [2] 2f c5 [2] 2d c4 [2] 36 c2 [2] 2a c5 [2] 36 ea }

  condition:
    any of them
}
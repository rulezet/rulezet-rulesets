rule TTP_XOR_QUAD_CurrentVersionRun_08b6 {
  strings:
    $key_08b6 = { 5b d9 [2] 7f d7 [2] 54 fb [2] 7a d9 [2] 6e c2 [2] 61 d8 [2] 7f c5 [2] 7d c4 [2] 66 c2 [2] 7a c5 [2] 66 ea }

  condition:
    any of them
}
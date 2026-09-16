rule TTP_XOR_QUAD_CurrentVersionRun_28b6 {
  strings:
    $key_28b6 = { 7b d9 [2] 5f d7 [2] 74 fb [2] 5a d9 [2] 4e c2 [2] 41 d8 [2] 5f c5 [2] 5d c4 [2] 46 c2 [2] 5a c5 [2] 46 ea }

  condition:
    any of them
}
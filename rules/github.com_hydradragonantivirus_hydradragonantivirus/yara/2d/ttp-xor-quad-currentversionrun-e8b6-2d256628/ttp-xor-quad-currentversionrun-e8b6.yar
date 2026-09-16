rule TTP_XOR_QUAD_CurrentVersionRun_e8b6 {
  strings:
    $key_e8b6 = { bb d9 [2] 9f d7 [2] b4 fb [2] 9a d9 [2] 8e c2 [2] 81 d8 [2] 9f c5 [2] 9d c4 [2] 86 c2 [2] 9a c5 [2] 86 ea }

  condition:
    any of them
}
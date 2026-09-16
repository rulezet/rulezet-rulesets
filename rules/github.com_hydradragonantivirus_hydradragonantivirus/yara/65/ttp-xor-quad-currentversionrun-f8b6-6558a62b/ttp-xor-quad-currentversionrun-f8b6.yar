rule TTP_XOR_QUAD_CurrentVersionRun_f8b6 {
  strings:
    $key_f8b6 = { ab d9 [2] 8f d7 [2] a4 fb [2] 8a d9 [2] 9e c2 [2] 91 d8 [2] 8f c5 [2] 8d c4 [2] 96 c2 [2] 8a c5 [2] 96 ea }

  condition:
    any of them
}
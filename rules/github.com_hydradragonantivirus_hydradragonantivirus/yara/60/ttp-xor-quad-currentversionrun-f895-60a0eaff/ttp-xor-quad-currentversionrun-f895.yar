rule TTP_XOR_QUAD_CurrentVersionRun_f895 {
  strings:
    $key_f895 = { ab fa [2] 8f f4 [2] a4 d8 [2] 8a fa [2] 9e e1 [2] 91 fb [2] 8f e6 [2] 8d e7 [2] 96 e1 [2] 8a e6 [2] 96 c9 }

  condition:
    any of them
}
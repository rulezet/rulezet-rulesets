rule TTP_XOR_QUAD_CurrentVersionRun_bc89 {
  strings:
    $key_bc89 = { ef e6 [2] cb e8 [2] e0 c4 [2] ce e6 [2] da fd [2] d5 e7 [2] cb fa [2] c9 fb [2] d2 fd [2] ce fa [2] d2 d5 }

  condition:
    any of them
}
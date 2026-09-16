rule TTP_XOR_QUAD_CurrentVersionRun_0395 {
  strings:
    $key_0395 = { 50 fa [2] 74 f4 [2] 5f d8 [2] 71 fa [2] 65 e1 [2] 6a fb [2] 74 e6 [2] 76 e7 [2] 6d e1 [2] 71 e6 [2] 6d c9 }

  condition:
    any of them
}
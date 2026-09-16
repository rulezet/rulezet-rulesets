rule TTP_XOR_QUAD_CurrentVersionRun_6395 {
  strings:
    $key_6395 = { 30 fa [2] 14 f4 [2] 3f d8 [2] 11 fa [2] 05 e1 [2] 0a fb [2] 14 e6 [2] 16 e7 [2] 0d e1 [2] 11 e6 [2] 0d c9 }

  condition:
    any of them
}
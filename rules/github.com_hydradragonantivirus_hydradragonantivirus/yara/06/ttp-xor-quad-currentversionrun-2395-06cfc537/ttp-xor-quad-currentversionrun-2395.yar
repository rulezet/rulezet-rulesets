rule TTP_XOR_QUAD_CurrentVersionRun_2395 {
  strings:
    $key_2395 = { 70 fa [2] 54 f4 [2] 7f d8 [2] 51 fa [2] 45 e1 [2] 4a fb [2] 54 e6 [2] 56 e7 [2] 4d e1 [2] 51 e6 [2] 4d c9 }

  condition:
    any of them
}
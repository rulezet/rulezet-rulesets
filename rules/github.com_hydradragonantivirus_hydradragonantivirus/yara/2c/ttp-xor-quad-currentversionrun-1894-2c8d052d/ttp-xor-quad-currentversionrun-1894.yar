rule TTP_XOR_QUAD_CurrentVersionRun_1894 {
  strings:
    $key_1894 = { 4b fb [2] 6f f5 [2] 44 d9 [2] 6a fb [2] 7e e0 [2] 71 fa [2] 6f e7 [2] 6d e6 [2] 76 e0 [2] 6a e7 [2] 76 c8 }

  condition:
    any of them
}
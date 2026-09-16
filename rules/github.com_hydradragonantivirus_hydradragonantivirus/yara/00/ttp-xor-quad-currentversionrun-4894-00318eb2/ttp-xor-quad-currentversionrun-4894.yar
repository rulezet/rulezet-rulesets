rule TTP_XOR_QUAD_CurrentVersionRun_4894 {
  strings:
    $key_4894 = { 1b fb [2] 3f f5 [2] 14 d9 [2] 3a fb [2] 2e e0 [2] 21 fa [2] 3f e7 [2] 3d e6 [2] 26 e0 [2] 3a e7 [2] 26 c8 }

  condition:
    any of them
}
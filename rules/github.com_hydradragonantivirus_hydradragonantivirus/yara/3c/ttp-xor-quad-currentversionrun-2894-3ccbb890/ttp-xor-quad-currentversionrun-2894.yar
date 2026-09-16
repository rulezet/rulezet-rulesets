rule TTP_XOR_QUAD_CurrentVersionRun_2894 {
  strings:
    $key_2894 = { 7b fb [2] 5f f5 [2] 74 d9 [2] 5a fb [2] 4e e0 [2] 41 fa [2] 5f e7 [2] 5d e6 [2] 46 e0 [2] 5a e7 [2] 46 c8 }

  condition:
    any of them
}
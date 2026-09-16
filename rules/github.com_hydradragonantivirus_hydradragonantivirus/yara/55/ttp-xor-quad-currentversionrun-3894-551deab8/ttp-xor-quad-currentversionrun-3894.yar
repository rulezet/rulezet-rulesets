rule TTP_XOR_QUAD_CurrentVersionRun_3894 {
  strings:
    $key_3894 = { 6b fb [2] 4f f5 [2] 64 d9 [2] 4a fb [2] 5e e0 [2] 51 fa [2] 4f e7 [2] 4d e6 [2] 56 e0 [2] 4a e7 [2] 56 c8 }

  condition:
    any of them
}
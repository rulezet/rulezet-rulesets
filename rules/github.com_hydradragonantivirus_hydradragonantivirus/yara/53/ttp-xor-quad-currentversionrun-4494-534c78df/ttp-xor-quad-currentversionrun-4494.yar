rule TTP_XOR_QUAD_CurrentVersionRun_4494 {
  strings:
    $key_4494 = { 17 fb [2] 33 f5 [2] 18 d9 [2] 36 fb [2] 22 e0 [2] 2d fa [2] 33 e7 [2] 31 e6 [2] 2a e0 [2] 36 e7 [2] 2a c8 }

  condition:
    any of them
}
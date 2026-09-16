rule TTP_XOR_QUAD_CurrentVersionRun_e494 {
  strings:
    $key_e494 = { b7 fb [2] 93 f5 [2] b8 d9 [2] 96 fb [2] 82 e0 [2] 8d fa [2] 93 e7 [2] 91 e6 [2] 8a e0 [2] 96 e7 [2] 8a c8 }

  condition:
    any of them
}
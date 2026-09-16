rule TTP_XOR_QUAD_CurrentVersionRun_2194 {
  strings:
    $key_2194 = { 72 fb [2] 56 f5 [2] 7d d9 [2] 53 fb [2] 47 e0 [2] 48 fa [2] 56 e7 [2] 54 e6 [2] 4f e0 [2] 53 e7 [2] 4f c8 }

  condition:
    any of them
}
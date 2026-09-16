rule TTP_XOR_QUAD_CurrentVersionRun_3194 {
  strings:
    $key_3194 = { 62 fb [2] 46 f5 [2] 6d d9 [2] 43 fb [2] 57 e0 [2] 58 fa [2] 46 e7 [2] 44 e6 [2] 5f e0 [2] 43 e7 [2] 5f c8 }

  condition:
    any of them
}
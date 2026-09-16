rule TTP_XOR_QUAD_CurrentVersionRun_5694 {
  strings:
    $key_5694 = { 05 fb [2] 21 f5 [2] 0a d9 [2] 24 fb [2] 30 e0 [2] 3f fa [2] 21 e7 [2] 23 e6 [2] 38 e0 [2] 24 e7 [2] 38 c8 }

  condition:
    any of them
}
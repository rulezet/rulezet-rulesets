rule TTP_XOR_QUAD_CurrentVersionRun_0694 {
  strings:
    $key_0694 = { 55 fb [2] 71 f5 [2] 5a d9 [2] 74 fb [2] 60 e0 [2] 6f fa [2] 71 e7 [2] 73 e6 [2] 68 e0 [2] 74 e7 [2] 68 c8 }

  condition:
    any of them
}
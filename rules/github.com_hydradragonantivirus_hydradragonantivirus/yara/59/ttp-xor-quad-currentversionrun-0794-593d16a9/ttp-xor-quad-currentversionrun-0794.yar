rule TTP_XOR_QUAD_CurrentVersionRun_0794 {
  strings:
    $key_0794 = { 54 fb [2] 70 f5 [2] 5b d9 [2] 75 fb [2] 61 e0 [2] 6e fa [2] 70 e7 [2] 72 e6 [2] 69 e0 [2] 75 e7 [2] 69 c8 }

  condition:
    any of them
}
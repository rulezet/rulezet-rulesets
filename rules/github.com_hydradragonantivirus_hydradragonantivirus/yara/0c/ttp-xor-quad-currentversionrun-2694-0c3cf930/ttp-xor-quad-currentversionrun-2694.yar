rule TTP_XOR_QUAD_CurrentVersionRun_2694 {
  strings:
    $key_2694 = { 75 fb [2] 51 f5 [2] 7a d9 [2] 54 fb [2] 40 e0 [2] 4f fa [2] 51 e7 [2] 53 e6 [2] 48 e0 [2] 54 e7 [2] 48 c8 }

  condition:
    any of them
}
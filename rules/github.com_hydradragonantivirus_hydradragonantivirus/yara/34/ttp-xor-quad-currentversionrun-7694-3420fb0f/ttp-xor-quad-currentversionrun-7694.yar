rule TTP_XOR_QUAD_CurrentVersionRun_7694 {
  strings:
    $key_7694 = { 25 fb [2] 01 f5 [2] 2a d9 [2] 04 fb [2] 10 e0 [2] 1f fa [2] 01 e7 [2] 03 e6 [2] 18 e0 [2] 04 e7 [2] 18 c8 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_e889 {
  strings:
    $key_e889 = { bb e6 [2] 9f e8 [2] b4 c4 [2] 9a e6 [2] 8e fd [2] 81 e7 [2] 9f fa [2] 9d fb [2] 86 fd [2] 9a fa [2] 86 d5 }

  condition:
    any of them
}
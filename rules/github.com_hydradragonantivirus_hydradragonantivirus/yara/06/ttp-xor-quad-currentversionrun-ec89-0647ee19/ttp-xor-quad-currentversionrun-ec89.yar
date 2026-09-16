rule TTP_XOR_QUAD_CurrentVersionRun_ec89 {
  strings:
    $key_ec89 = { bf e6 [2] 9b e8 [2] b0 c4 [2] 9e e6 [2] 8a fd [2] 85 e7 [2] 9b fa [2] 99 fb [2] 82 fd [2] 9e fa [2] 82 d5 }

  condition:
    any of them
}
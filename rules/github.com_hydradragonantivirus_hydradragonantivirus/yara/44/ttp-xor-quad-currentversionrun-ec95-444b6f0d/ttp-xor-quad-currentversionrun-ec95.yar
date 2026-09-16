rule TTP_XOR_QUAD_CurrentVersionRun_ec95 {
  strings:
    $key_ec95 = { bf fa [2] 9b f4 [2] b0 d8 [2] 9e fa [2] 8a e1 [2] 85 fb [2] 9b e6 [2] 99 e7 [2] 82 e1 [2] 9e e6 [2] 82 c9 }

  condition:
    any of them
}
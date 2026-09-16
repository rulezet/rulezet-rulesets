rule TTP_XOR_QUAD_CurrentVersionRun_fd89 {
  strings:
    $key_fd89 = { ae e6 [2] 8a e8 [2] a1 c4 [2] 8f e6 [2] 9b fd [2] 94 e7 [2] 8a fa [2] 88 fb [2] 93 fd [2] 8f fa [2] 93 d5 }

  condition:
    any of them
}
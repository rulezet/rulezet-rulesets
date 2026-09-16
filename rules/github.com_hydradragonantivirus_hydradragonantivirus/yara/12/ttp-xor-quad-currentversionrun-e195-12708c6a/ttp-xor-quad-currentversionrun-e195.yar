rule TTP_XOR_QUAD_CurrentVersionRun_e195 {
  strings:
    $key_e195 = { b2 fa [2] 96 f4 [2] bd d8 [2] 93 fa [2] 87 e1 [2] 88 fb [2] 96 e6 [2] 94 e7 [2] 8f e1 [2] 93 e6 [2] 8f c9 }

  condition:
    any of them
}
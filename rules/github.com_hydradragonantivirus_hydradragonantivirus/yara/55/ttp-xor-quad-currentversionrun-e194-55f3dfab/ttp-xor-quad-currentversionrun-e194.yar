rule TTP_XOR_QUAD_CurrentVersionRun_e194 {
  strings:
    $key_e194 = { b2 fb [2] 96 f5 [2] bd d9 [2] 93 fb [2] 87 e0 [2] 88 fa [2] 96 e7 [2] 94 e6 [2] 8f e0 [2] 93 e7 [2] 8f c8 }

  condition:
    any of them
}
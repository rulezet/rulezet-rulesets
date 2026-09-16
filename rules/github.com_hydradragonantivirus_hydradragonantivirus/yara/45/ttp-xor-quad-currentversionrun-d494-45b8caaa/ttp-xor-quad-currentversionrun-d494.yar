rule TTP_XOR_QUAD_CurrentVersionRun_d494 {
  strings:
    $key_d494 = { 87 fb [2] a3 f5 [2] 88 d9 [2] a6 fb [2] b2 e0 [2] bd fa [2] a3 e7 [2] a1 e6 [2] ba e0 [2] a6 e7 [2] ba c8 }

  condition:
    any of them
}
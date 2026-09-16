rule TTP_XOR_QUAD_CurrentVersionRun_0a95 {
  strings:
    $key_0a95 = { 59 fa [2] 7d f4 [2] 56 d8 [2] 78 fa [2] 6c e1 [2] 63 fb [2] 7d e6 [2] 7f e7 [2] 64 e1 [2] 78 e6 [2] 64 c9 }

  condition:
    any of them
}
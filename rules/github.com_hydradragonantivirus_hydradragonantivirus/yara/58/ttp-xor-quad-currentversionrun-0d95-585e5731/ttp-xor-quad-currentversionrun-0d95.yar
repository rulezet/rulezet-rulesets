rule TTP_XOR_QUAD_CurrentVersionRun_0d95 {
  strings:
    $key_0d95 = { 5e fa [2] 7a f4 [2] 51 d8 [2] 7f fa [2] 6b e1 [2] 64 fb [2] 7a e6 [2] 78 e7 [2] 63 e1 [2] 7f e6 [2] 63 c9 }

  condition:
    any of them
}
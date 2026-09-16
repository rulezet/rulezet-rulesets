rule TTP_XOR_QUAD_CurrentVersionRun_1d95 {
  strings:
    $key_1d95 = { 4e fa [2] 6a f4 [2] 41 d8 [2] 6f fa [2] 7b e1 [2] 74 fb [2] 6a e6 [2] 68 e7 [2] 73 e1 [2] 6f e6 [2] 73 c9 }

  condition:
    any of them
}
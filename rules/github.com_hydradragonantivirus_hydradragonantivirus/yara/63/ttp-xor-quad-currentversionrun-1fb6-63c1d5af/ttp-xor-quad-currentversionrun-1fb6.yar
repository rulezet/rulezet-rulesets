rule TTP_XOR_QUAD_CurrentVersionRun_1fb6 {
  strings:
    $key_1fb6 = { 4c d9 [2] 68 d7 [2] 43 fb [2] 6d d9 [2] 79 c2 [2] 76 d8 [2] 68 c5 [2] 6a c4 [2] 71 c2 [2] 6d c5 [2] 71 ea }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_04b6 {
  strings:
    $key_04b6 = { 57 d9 [2] 73 d7 [2] 58 fb [2] 76 d9 [2] 62 c2 [2] 6d d8 [2] 73 c5 [2] 71 c4 [2] 6a c2 [2] 76 c5 [2] 6a ea }

  condition:
    any of them
}
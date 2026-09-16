rule TTP_XOR_QUAD_CurrentVersionRun_019a {
  strings:
    $key_019a = { 52 f5 [2] 76 fb [2] 5d d7 [2] 73 f5 [2] 67 ee [2] 68 f4 [2] 76 e9 [2] 74 e8 [2] 6f ee [2] 73 e9 [2] 6f c6 }

  condition:
    any of them
}
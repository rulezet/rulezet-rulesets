rule TTP_XOR_QUAD_CurrentVersionRun_519a {
  strings:
    $key_519a = { 02 f5 [2] 26 fb [2] 0d d7 [2] 23 f5 [2] 37 ee [2] 38 f4 [2] 26 e9 [2] 24 e8 [2] 3f ee [2] 23 e9 [2] 3f c6 }

  condition:
    any of them
}
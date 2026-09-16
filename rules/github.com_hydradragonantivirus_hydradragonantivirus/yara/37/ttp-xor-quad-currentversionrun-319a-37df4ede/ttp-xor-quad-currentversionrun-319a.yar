rule TTP_XOR_QUAD_CurrentVersionRun_319a {
  strings:
    $key_319a = { 62 f5 [2] 46 fb [2] 6d d7 [2] 43 f5 [2] 57 ee [2] 58 f4 [2] 46 e9 [2] 44 e8 [2] 5f ee [2] 43 e9 [2] 5f c6 }

  condition:
    any of them
}
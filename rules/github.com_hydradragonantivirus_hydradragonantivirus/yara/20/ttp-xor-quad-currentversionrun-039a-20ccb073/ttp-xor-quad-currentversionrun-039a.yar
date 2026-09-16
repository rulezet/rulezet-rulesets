rule TTP_XOR_QUAD_CurrentVersionRun_039a {
  strings:
    $key_039a = { 50 f5 [2] 74 fb [2] 5f d7 [2] 71 f5 [2] 65 ee [2] 6a f4 [2] 74 e9 [2] 76 e8 [2] 6d ee [2] 71 e9 [2] 6d c6 }

  condition:
    any of them
}
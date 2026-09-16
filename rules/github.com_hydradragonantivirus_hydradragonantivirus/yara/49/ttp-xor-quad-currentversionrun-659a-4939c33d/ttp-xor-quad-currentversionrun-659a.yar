rule TTP_XOR_QUAD_CurrentVersionRun_659a {
  strings:
    $key_659a = { 36 f5 [2] 12 fb [2] 39 d7 [2] 17 f5 [2] 03 ee [2] 0c f4 [2] 12 e9 [2] 10 e8 [2] 0b ee [2] 17 e9 [2] 0b c6 }

  condition:
    any of them
}
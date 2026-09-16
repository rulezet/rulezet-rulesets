rule TTP_XOR_QUAD_CurrentVersionRun_559a {
  strings:
    $key_559a = { 06 f5 [2] 22 fb [2] 09 d7 [2] 27 f5 [2] 33 ee [2] 3c f4 [2] 22 e9 [2] 20 e8 [2] 3b ee [2] 27 e9 [2] 3b c6 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_3f9a {
  strings:
    $key_3f9a = { 6c f5 [2] 48 fb [2] 63 d7 [2] 4d f5 [2] 59 ee [2] 56 f4 [2] 48 e9 [2] 4a e8 [2] 51 ee [2] 4d e9 [2] 51 c6 }

  condition:
    any of them
}
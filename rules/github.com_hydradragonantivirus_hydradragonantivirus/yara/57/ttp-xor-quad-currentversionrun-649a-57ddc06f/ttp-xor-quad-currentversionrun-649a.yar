rule TTP_XOR_QUAD_CurrentVersionRun_649a {
  strings:
    $key_649a = { 37 f5 [2] 13 fb [2] 38 d7 [2] 16 f5 [2] 02 ee [2] 0d f4 [2] 13 e9 [2] 11 e8 [2] 0a ee [2] 16 e9 [2] 0a c6 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_e39a {
  strings:
    $key_e39a = { b0 f5 [2] 94 fb [2] bf d7 [2] 91 f5 [2] 85 ee [2] 8a f4 [2] 94 e9 [2] 96 e8 [2] 8d ee [2] 91 e9 [2] 8d c6 }

  condition:
    any of them
}
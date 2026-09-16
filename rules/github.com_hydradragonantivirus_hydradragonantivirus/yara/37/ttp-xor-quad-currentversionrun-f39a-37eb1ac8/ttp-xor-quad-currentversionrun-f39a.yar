rule TTP_XOR_QUAD_CurrentVersionRun_f39a {
  strings:
    $key_f39a = { a0 f5 [2] 84 fb [2] af d7 [2] 81 f5 [2] 95 ee [2] 9a f4 [2] 84 e9 [2] 86 e8 [2] 9d ee [2] 81 e9 [2] 9d c6 }

  condition:
    any of them
}
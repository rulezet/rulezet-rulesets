rule TTP_XOR_QUAD_CurrentVersionRun_f19a {
  strings:
    $key_f19a = { a2 f5 [2] 86 fb [2] ad d7 [2] 83 f5 [2] 97 ee [2] 98 f4 [2] 86 e9 [2] 84 e8 [2] 9f ee [2] 83 e9 [2] 9f c6 }

  condition:
    any of them
}
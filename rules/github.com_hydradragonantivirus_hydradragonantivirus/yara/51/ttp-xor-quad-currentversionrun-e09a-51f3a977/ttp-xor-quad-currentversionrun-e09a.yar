rule TTP_XOR_QUAD_CurrentVersionRun_e09a {
  strings:
    $key_e09a = { b3 f5 [2] 97 fb [2] bc d7 [2] 92 f5 [2] 86 ee [2] 89 f4 [2] 97 e9 [2] 95 e8 [2] 8e ee [2] 92 e9 [2] 8e c6 }

  condition:
    any of them
}
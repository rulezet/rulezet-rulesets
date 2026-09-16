rule TTP_XOR_QUAD_CurrentVersionRun_e087 {
  strings:
    $key_e087 = { b3 e8 [2] 97 e6 [2] bc ca [2] 92 e8 [2] 86 f3 [2] 89 e9 [2] 97 f4 [2] 95 f5 [2] 8e f3 [2] 92 f4 [2] 8e db }

  condition:
    any of them
}
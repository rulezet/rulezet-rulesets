rule TTP_XOR_QUAD_CurrentVersionRun_1cb6 {
  strings:
    $key_1cb6 = { 4f d9 [2] 6b d7 [2] 40 fb [2] 6e d9 [2] 7a c2 [2] 75 d8 [2] 6b c5 [2] 69 c4 [2] 72 c2 [2] 6e c5 [2] 72 ea }

  condition:
    any of them
}
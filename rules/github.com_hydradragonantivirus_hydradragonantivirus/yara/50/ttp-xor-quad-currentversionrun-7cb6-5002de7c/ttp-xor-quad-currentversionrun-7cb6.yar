rule TTP_XOR_QUAD_CurrentVersionRun_7cb6 {
  strings:
    $key_7cb6 = { 2f d9 [2] 0b d7 [2] 20 fb [2] 0e d9 [2] 1a c2 [2] 15 d8 [2] 0b c5 [2] 09 c4 [2] 12 c2 [2] 0e c5 [2] 12 ea }

  condition:
    any of them
}
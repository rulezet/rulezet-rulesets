rule TTP_XOR_QUAD_CurrentVersionRun_5cb6 {
  strings:
    $key_5cb6 = { 0f d9 [2] 2b d7 [2] 00 fb [2] 2e d9 [2] 3a c2 [2] 35 d8 [2] 2b c5 [2] 29 c4 [2] 32 c2 [2] 2e c5 [2] 32 ea }

  condition:
    any of them
}
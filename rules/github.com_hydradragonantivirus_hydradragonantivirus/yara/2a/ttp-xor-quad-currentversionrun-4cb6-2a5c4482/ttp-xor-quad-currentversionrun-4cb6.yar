rule TTP_XOR_QUAD_CurrentVersionRun_4cb6 {
  strings:
    $key_4cb6 = { 1f d9 [2] 3b d7 [2] 10 fb [2] 3e d9 [2] 2a c2 [2] 25 d8 [2] 3b c5 [2] 39 c4 [2] 22 c2 [2] 3e c5 [2] 22 ea }

  condition:
    any of them
}
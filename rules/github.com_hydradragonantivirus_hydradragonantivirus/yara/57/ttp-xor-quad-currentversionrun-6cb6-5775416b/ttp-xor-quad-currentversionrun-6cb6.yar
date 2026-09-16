rule TTP_XOR_QUAD_CurrentVersionRun_6cb6 {
  strings:
    $key_6cb6 = { 3f d9 [2] 1b d7 [2] 30 fb [2] 1e d9 [2] 0a c2 [2] 05 d8 [2] 1b c5 [2] 19 c4 [2] 02 c2 [2] 1e c5 [2] 02 ea }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_3cb6 {
  strings:
    $key_3cb6 = { 6f d9 [2] 4b d7 [2] 60 fb [2] 4e d9 [2] 5a c2 [2] 55 d8 [2] 4b c5 [2] 49 c4 [2] 52 c2 [2] 4e c5 [2] 52 ea }

  condition:
    any of them
}
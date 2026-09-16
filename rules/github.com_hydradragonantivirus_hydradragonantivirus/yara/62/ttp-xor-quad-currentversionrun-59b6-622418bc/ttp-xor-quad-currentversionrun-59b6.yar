rule TTP_XOR_QUAD_CurrentVersionRun_59b6 {
  strings:
    $key_59b6 = { 0a d9 [2] 2e d7 [2] 05 fb [2] 2b d9 [2] 3f c2 [2] 30 d8 [2] 2e c5 [2] 2c c4 [2] 37 c2 [2] 2b c5 [2] 37 ea }

  condition:
    any of them
}
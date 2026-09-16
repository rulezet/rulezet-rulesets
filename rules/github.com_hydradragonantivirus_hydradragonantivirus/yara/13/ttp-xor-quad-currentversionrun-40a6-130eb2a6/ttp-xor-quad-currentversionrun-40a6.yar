rule TTP_XOR_QUAD_CurrentVersionRun_40a6 {
  strings:
    $key_40a6 = { 13 c9 [2] 37 c7 [2] 1c eb [2] 32 c9 [2] 26 d2 [2] 29 c8 [2] 37 d5 [2] 35 d4 [2] 2e d2 [2] 32 d5 [2] 2e fa }

  condition:
    any of them
}
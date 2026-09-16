rule TTP_XOR_QUAD_CurrentVersionRun_7aba {
  strings:
    $key_7aba = { 29 d5 [2] 0d db [2] 26 f7 [2] 08 d5 [2] 1c ce [2] 13 d4 [2] 0d c9 [2] 0f c8 [2] 14 ce [2] 08 c9 [2] 14 e6 }

  condition:
    any of them
}
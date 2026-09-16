rule TTP_XOR_QUAD_CurrentVersionRun_3aba {
  strings:
    $key_3aba = { 69 d5 [2] 4d db [2] 66 f7 [2] 48 d5 [2] 5c ce [2] 53 d4 [2] 4d c9 [2] 4f c8 [2] 54 ce [2] 48 c9 [2] 54 e6 }

  condition:
    any of them
}
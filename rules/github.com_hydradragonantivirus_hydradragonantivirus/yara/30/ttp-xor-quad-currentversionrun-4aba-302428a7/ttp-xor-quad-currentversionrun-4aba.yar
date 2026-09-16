rule TTP_XOR_QUAD_CurrentVersionRun_4aba {
  strings:
    $key_4aba = { 19 d5 [2] 3d db [2] 16 f7 [2] 38 d5 [2] 2c ce [2] 23 d4 [2] 3d c9 [2] 3f c8 [2] 24 ce [2] 38 c9 [2] 24 e6 }

  condition:
    any of them
}
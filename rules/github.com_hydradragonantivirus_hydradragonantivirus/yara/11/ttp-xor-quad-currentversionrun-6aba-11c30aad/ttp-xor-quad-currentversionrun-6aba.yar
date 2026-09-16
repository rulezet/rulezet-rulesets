rule TTP_XOR_QUAD_CurrentVersionRun_6aba {
  strings:
    $key_6aba = { 39 d5 [2] 1d db [2] 36 f7 [2] 18 d5 [2] 0c ce [2] 03 d4 [2] 1d c9 [2] 1f c8 [2] 04 ce [2] 18 c9 [2] 04 e6 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_5cab {
  strings:
    $key_5cab = { 0f c4 [2] 2b ca [2] 00 e6 [2] 2e c4 [2] 3a df [2] 35 c5 [2] 2b d8 [2] 29 d9 [2] 32 df [2] 2e d8 [2] 32 f7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_69ab {
  strings:
    $key_69ab = { 3a c4 [2] 1e ca [2] 35 e6 [2] 1b c4 [2] 0f df [2] 00 c5 [2] 1e d8 [2] 1c d9 [2] 07 df [2] 1b d8 [2] 07 f7 }

  condition:
    any of them
}
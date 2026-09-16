rule TTP_XOR_QUAD_CurrentVersionRun_e9ab {
  strings:
    $key_e9ab = { ba c4 [2] 9e ca [2] b5 e6 [2] 9b c4 [2] 8f df [2] 80 c5 [2] 9e d8 [2] 9c d9 [2] 87 df [2] 9b d8 [2] 87 f7 }

  condition:
    any of them
}
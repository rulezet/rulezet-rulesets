rule TTP_XOR_QUAD_CurrentVersionRun_79ab {
  strings:
    $key_79ab = { 2a c4 [2] 0e ca [2] 25 e6 [2] 0b c4 [2] 1f df [2] 10 c5 [2] 0e d8 [2] 0c d9 [2] 17 df [2] 0b d8 [2] 17 f7 }

  condition:
    any of them
}
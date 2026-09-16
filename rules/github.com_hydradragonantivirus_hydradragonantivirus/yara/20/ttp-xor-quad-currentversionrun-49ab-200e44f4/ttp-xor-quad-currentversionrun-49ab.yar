rule TTP_XOR_QUAD_CurrentVersionRun_49ab {
  strings:
    $key_49ab = { 1a c4 [2] 3e ca [2] 15 e6 [2] 3b c4 [2] 2f df [2] 20 c5 [2] 3e d8 [2] 3c d9 [2] 27 df [2] 3b d8 [2] 27 f7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_29ab {
  strings:
    $key_29ab = { 7a c4 [2] 5e ca [2] 75 e6 [2] 5b c4 [2] 4f df [2] 40 c5 [2] 5e d8 [2] 5c d9 [2] 47 df [2] 5b d8 [2] 47 f7 }

  condition:
    any of them
}
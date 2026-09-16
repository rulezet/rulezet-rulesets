rule TTP_XOR_QUAD_CurrentVersionRun_19ab {
  strings:
    $key_19ab = { 4a c4 [2] 6e ca [2] 45 e6 [2] 6b c4 [2] 7f df [2] 70 c5 [2] 6e d8 [2] 6c d9 [2] 77 df [2] 6b d8 [2] 77 f7 }

  condition:
    any of them
}
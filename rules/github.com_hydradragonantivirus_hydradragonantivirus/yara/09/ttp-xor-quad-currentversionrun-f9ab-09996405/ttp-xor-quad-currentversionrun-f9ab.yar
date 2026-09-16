rule TTP_XOR_QUAD_CurrentVersionRun_f9ab {
  strings:
    $key_f9ab = { aa c4 [2] 8e ca [2] a5 e6 [2] 8b c4 [2] 9f df [2] 90 c5 [2] 8e d8 [2] 8c d9 [2] 97 df [2] 8b d8 [2] 97 f7 }

  condition:
    any of them
}
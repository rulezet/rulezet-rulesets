rule TTP_XOR_QUAD_CurrentVersionRun_1bab {
  strings:
    $key_1bab = { 48 c4 [2] 6c ca [2] 47 e6 [2] 69 c4 [2] 7d df [2] 72 c5 [2] 6c d8 [2] 6e d9 [2] 75 df [2] 69 d8 [2] 75 f7 }

  condition:
    any of them
}
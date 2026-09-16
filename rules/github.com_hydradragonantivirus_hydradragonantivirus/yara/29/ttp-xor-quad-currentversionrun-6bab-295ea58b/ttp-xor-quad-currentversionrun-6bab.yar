rule TTP_XOR_QUAD_CurrentVersionRun_6bab {
  strings:
    $key_6bab = { 38 c4 [2] 1c ca [2] 37 e6 [2] 19 c4 [2] 0d df [2] 02 c5 [2] 1c d8 [2] 1e d9 [2] 05 df [2] 19 d8 [2] 05 f7 }

  condition:
    any of them
}
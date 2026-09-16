rule TTP_XOR_QUAD_CurrentVersionRun_4bab {
  strings:
    $key_4bab = { 18 c4 [2] 3c ca [2] 17 e6 [2] 39 c4 [2] 2d df [2] 22 c5 [2] 3c d8 [2] 3e d9 [2] 25 df [2] 39 d8 [2] 25 f7 }

  condition:
    any of them
}
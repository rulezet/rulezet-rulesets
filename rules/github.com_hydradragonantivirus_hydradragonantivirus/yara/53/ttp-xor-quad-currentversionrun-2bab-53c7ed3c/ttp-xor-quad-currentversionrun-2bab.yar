rule TTP_XOR_QUAD_CurrentVersionRun_2bab {
  strings:
    $key_2bab = { 78 c4 [2] 5c ca [2] 77 e6 [2] 59 c4 [2] 4d df [2] 42 c5 [2] 5c d8 [2] 5e d9 [2] 45 df [2] 59 d8 [2] 45 f7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2cab {
  strings:
    $key_2cab = { 7f c4 [2] 5b ca [2] 70 e6 [2] 5e c4 [2] 4a df [2] 45 c5 [2] 5b d8 [2] 59 d9 [2] 42 df [2] 5e d8 [2] 42 f7 }

  condition:
    any of them
}
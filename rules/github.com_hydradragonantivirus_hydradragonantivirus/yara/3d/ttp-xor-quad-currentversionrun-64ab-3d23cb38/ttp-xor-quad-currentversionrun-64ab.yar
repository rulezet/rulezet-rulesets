rule TTP_XOR_QUAD_CurrentVersionRun_64ab {
  strings:
    $key_64ab = { 37 c4 [2] 13 ca [2] 38 e6 [2] 16 c4 [2] 02 df [2] 0d c5 [2] 13 d8 [2] 11 d9 [2] 0a df [2] 16 d8 [2] 0a f7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_60ab {
  strings:
    $key_60ab = { 33 c4 [2] 17 ca [2] 3c e6 [2] 12 c4 [2] 06 df [2] 09 c5 [2] 17 d8 [2] 15 d9 [2] 0e df [2] 12 d8 [2] 0e f7 }

  condition:
    any of them
}
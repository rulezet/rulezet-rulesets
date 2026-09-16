rule TTP_XOR_QUAD_CurrentVersionRun_73ab {
  strings:
    $key_73ab = { 20 c4 [2] 04 ca [2] 2f e6 [2] 01 c4 [2] 15 df [2] 1a c5 [2] 04 d8 [2] 06 d9 [2] 1d df [2] 01 d8 [2] 1d f7 }

  condition:
    any of them
}
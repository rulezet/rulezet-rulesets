rule TTP_XOR_QUAD_CurrentVersionRun_40ab {
  strings:
    $key_40ab = { 13 c4 [2] 37 ca [2] 1c e6 [2] 32 c4 [2] 26 df [2] 29 c5 [2] 37 d8 [2] 35 d9 [2] 2e df [2] 32 d8 [2] 2e f7 }

  condition:
    any of them
}
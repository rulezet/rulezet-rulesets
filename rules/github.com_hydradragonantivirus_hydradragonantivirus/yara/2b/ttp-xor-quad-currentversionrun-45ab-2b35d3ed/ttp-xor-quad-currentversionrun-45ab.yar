rule TTP_XOR_QUAD_CurrentVersionRun_45ab {
  strings:
    $key_45ab = { 16 c4 [2] 32 ca [2] 19 e6 [2] 37 c4 [2] 23 df [2] 2c c5 [2] 32 d8 [2] 30 d9 [2] 2b df [2] 37 d8 [2] 2b f7 }

  condition:
    any of them
}
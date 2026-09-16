rule TTP_XOR_QUAD_CurrentVersionRun_22ab {
  strings:
    $key_22ab = { 71 c4 [2] 55 ca [2] 7e e6 [2] 50 c4 [2] 44 df [2] 4b c5 [2] 55 d8 [2] 57 d9 [2] 4c df [2] 50 d8 [2] 4c f7 }

  condition:
    any of them
}
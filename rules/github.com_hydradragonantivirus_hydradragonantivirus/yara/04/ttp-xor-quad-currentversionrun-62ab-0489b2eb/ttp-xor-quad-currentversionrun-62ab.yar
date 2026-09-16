rule TTP_XOR_QUAD_CurrentVersionRun_62ab {
  strings:
    $key_62ab = { 31 c4 [2] 15 ca [2] 3e e6 [2] 10 c4 [2] 04 df [2] 0b c5 [2] 15 d8 [2] 17 d9 [2] 0c df [2] 10 d8 [2] 0c f7 }

  condition:
    any of them
}
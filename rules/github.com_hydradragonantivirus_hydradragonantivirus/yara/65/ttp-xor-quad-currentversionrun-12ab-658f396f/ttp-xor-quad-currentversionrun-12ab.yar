rule TTP_XOR_QUAD_CurrentVersionRun_12ab {
  strings:
    $key_12ab = { 41 c4 [2] 65 ca [2] 4e e6 [2] 60 c4 [2] 74 df [2] 7b c5 [2] 65 d8 [2] 67 d9 [2] 7c df [2] 60 d8 [2] 7c f7 }

  condition:
    any of them
}
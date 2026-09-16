rule TTP_XOR_QUAD_CurrentVersionRun_b3ab {
  strings:
    $key_b3ab = { e0 c4 [2] c4 ca [2] ef e6 [2] c1 c4 [2] d5 df [2] da c5 [2] c4 d8 [2] c6 d9 [2] dd df [2] c1 d8 [2] dd f7 }

  condition:
    any of them
}
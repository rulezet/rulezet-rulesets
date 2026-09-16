rule TTP_XOR_QUAD_CurrentVersionRun_a6ab {
  strings:
    $key_a6ab = { f5 c4 [2] d1 ca [2] fa e6 [2] d4 c4 [2] c0 df [2] cf c5 [2] d1 d8 [2] d3 d9 [2] c8 df [2] d4 d8 [2] c8 f7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a7ab {
  strings:
    $key_a7ab = { f4 c4 [2] d0 ca [2] fb e6 [2] d5 c4 [2] c1 df [2] ce c5 [2] d0 d8 [2] d2 d9 [2] c9 df [2] d5 d8 [2] c9 f7 }

  condition:
    any of them
}
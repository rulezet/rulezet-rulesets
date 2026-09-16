rule TTP_XOR_QUAD_CurrentVersionRun_b7ab {
  strings:
    $key_b7ab = { e4 c4 [2] c0 ca [2] eb e6 [2] c5 c4 [2] d1 df [2] de c5 [2] c0 d8 [2] c2 d9 [2] d9 df [2] c5 d8 [2] d9 f7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_b6ab {
  strings:
    $key_b6ab = { e5 c4 [2] c1 ca [2] ea e6 [2] c4 c4 [2] d0 df [2] df c5 [2] c1 d8 [2] c3 d9 [2] d8 df [2] c4 d8 [2] d8 f7 }

  condition:
    any of them
}
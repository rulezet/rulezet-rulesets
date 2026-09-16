rule TTP_XOR_QUAD_CurrentVersionRun_b2ab {
  strings:
    $key_b2ab = { e1 c4 [2] c5 ca [2] ee e6 [2] c0 c4 [2] d4 df [2] db c5 [2] c5 d8 [2] c7 d9 [2] dc df [2] c0 d8 [2] dc f7 }

  condition:
    any of them
}
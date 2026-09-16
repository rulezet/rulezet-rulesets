rule TTP_XOR_QUAD_CurrentVersionRun_b5a6 {
  strings:
    $key_b5a6 = { e6 c9 [2] c2 c7 [2] e9 eb [2] c7 c9 [2] d3 d2 [2] dc c8 [2] c2 d5 [2] c0 d4 [2] db d2 [2] c7 d5 [2] db fa }

  condition:
    any of them
}
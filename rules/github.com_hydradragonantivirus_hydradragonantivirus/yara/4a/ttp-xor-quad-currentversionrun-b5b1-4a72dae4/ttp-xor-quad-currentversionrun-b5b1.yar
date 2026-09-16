rule TTP_XOR_QUAD_CurrentVersionRun_b5b1 {
  strings:
    $key_b5b1 = { e6 de [2] c2 d0 [2] e9 fc [2] c7 de [2] d3 c5 [2] dc df [2] c2 c2 [2] c0 c3 [2] db c5 [2] c7 c2 [2] db ed }

  condition:
    any of them
}
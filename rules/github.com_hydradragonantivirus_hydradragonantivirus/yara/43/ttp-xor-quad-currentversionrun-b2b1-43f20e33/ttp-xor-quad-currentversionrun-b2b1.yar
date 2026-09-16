rule TTP_XOR_QUAD_CurrentVersionRun_b2b1 {
  strings:
    $key_b2b1 = { e1 de [2] c5 d0 [2] ee fc [2] c0 de [2] d4 c5 [2] db df [2] c5 c2 [2] c7 c3 [2] dc c5 [2] c0 c2 [2] dc ed }

  condition:
    any of them
}
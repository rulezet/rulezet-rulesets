rule TTP_XOR_QUAD_CurrentVersionRun_b1b1 {
  strings:
    $key_b1b1 = { e2 de [2] c6 d0 [2] ed fc [2] c3 de [2] d7 c5 [2] d8 df [2] c6 c2 [2] c4 c3 [2] df c5 [2] c3 c2 [2] df ed }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_b6b1 {
  strings:
    $key_b6b1 = { e5 de [2] c1 d0 [2] ea fc [2] c4 de [2] d0 c5 [2] df df [2] c1 c2 [2] c3 c3 [2] d8 c5 [2] c4 c2 [2] d8 ed }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_b7b1 {
  strings:
    $key_b7b1 = { e4 de [2] c0 d0 [2] eb fc [2] c5 de [2] d1 c5 [2] de df [2] c0 c2 [2] c2 c3 [2] d9 c5 [2] c5 c2 [2] d9 ed }

  condition:
    any of them
}
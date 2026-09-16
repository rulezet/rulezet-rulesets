rule TTP_XOR_QUAD_CurrentVersionRun_b7ac {
  strings:
    $key_b7ac = { e4 c3 [2] c0 cd [2] eb e1 [2] c5 c3 [2] d1 d8 [2] de c2 [2] c0 df [2] c2 de [2] d9 d8 [2] c5 df [2] d9 f0 }

  condition:
    any of them
}
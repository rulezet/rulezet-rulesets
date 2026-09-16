rule TTP_XOR_QUAD_CurrentVersionRun_b5ac {
  strings:
    $key_b5ac = { e6 c3 [2] c2 cd [2] e9 e1 [2] c7 c3 [2] d3 d8 [2] dc c2 [2] c2 df [2] c0 de [2] db d8 [2] c7 df [2] db f0 }

  condition:
    any of them
}
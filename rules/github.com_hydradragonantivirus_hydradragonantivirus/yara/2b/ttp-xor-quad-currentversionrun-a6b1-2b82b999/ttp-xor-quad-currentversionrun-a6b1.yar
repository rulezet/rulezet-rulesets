rule TTP_XOR_QUAD_CurrentVersionRun_a6b1 {
  strings:
    $key_a6b1 = { f5 de [2] d1 d0 [2] fa fc [2] d4 de [2] c0 c5 [2] cf df [2] d1 c2 [2] d3 c3 [2] c8 c5 [2] d4 c2 [2] c8 ed }

  condition:
    any of them
}
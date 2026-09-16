rule TTP_XOR_QUAD_CurrentVersionRun_a1ad {
  strings:
    $key_a1ad = { f2 c2 [2] d6 cc [2] fd e0 [2] d3 c2 [2] c7 d9 [2] c8 c3 [2] d6 de [2] d4 df [2] cf d9 [2] d3 de [2] cf f1 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a1a2 {
  strings:
    $key_a1a2 = { f2 cd [2] d6 c3 [2] fd ef [2] d3 cd [2] c7 d6 [2] c8 cc [2] d6 d1 [2] d4 d0 [2] cf d6 [2] d3 d1 [2] cf fe }

  condition:
    any of them
}
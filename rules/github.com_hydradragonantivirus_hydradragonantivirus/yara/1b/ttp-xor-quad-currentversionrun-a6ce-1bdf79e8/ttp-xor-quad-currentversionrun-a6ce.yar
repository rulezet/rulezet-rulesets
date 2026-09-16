rule TTP_XOR_QUAD_CurrentVersionRun_a6ce {
  strings:
    $key_a6ce = { f5 a1 [2] d1 af [2] fa 83 [2] d4 a1 [2] c0 ba [2] cf a0 [2] d1 bd [2] d3 bc [2] c8 ba [2] d4 bd [2] c8 92 }

  condition:
    any of them
}
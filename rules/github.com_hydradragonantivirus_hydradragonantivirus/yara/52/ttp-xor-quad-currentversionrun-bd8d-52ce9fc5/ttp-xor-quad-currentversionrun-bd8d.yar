rule TTP_XOR_QUAD_CurrentVersionRun_bd8d {
  strings:
    $key_bd8d = { ee e2 [2] ca ec [2] e1 c0 [2] cf e2 [2] db f9 [2] d4 e3 [2] ca fe [2] c8 ff [2] d3 f9 [2] cf fe [2] d3 d1 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a691 {
  strings:
    $key_a691 = { f5 fe [2] d1 f0 [2] fa dc [2] d4 fe [2] c0 e5 [2] cf ff [2] d1 e2 [2] d3 e3 [2] c8 e5 [2] d4 e2 [2] c8 cd }

  condition:
    any of them
}
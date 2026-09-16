rule TTP_XOR_QUAD_CurrentVersionRun_a191 {
  strings:
    $key_a191 = { f2 fe [2] d6 f0 [2] fd dc [2] d3 fe [2] c7 e5 [2] c8 ff [2] d6 e2 [2] d4 e3 [2] cf e5 [2] d3 e2 [2] cf cd }

  condition:
    any of them
}
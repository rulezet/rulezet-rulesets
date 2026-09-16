rule TTP_XOR_QUAD_CurrentVersionRun_a693 {
  strings:
    $key_a693 = { f5 fc [2] d1 f2 [2] fa de [2] d4 fc [2] c0 e7 [2] cf fd [2] d1 e0 [2] d3 e1 [2] c8 e7 [2] d4 e0 [2] c8 cf }

  condition:
    any of them
}
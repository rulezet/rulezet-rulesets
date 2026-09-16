rule TTP_XOR_QUAD_CurrentVersionRun_a193 {
  strings:
    $key_a193 = { f2 fc [2] d6 f2 [2] fd de [2] d3 fc [2] c7 e7 [2] c8 fd [2] d6 e0 [2] d4 e1 [2] cf e7 [2] d3 e0 [2] cf cf }

  condition:
    any of them
}
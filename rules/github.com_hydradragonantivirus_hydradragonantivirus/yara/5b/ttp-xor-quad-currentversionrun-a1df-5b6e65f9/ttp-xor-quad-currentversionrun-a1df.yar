rule TTP_XOR_QUAD_CurrentVersionRun_a1df {
  strings:
    $key_a1df = { f2 b0 [2] d6 be [2] fd 92 [2] d3 b0 [2] c7 ab [2] c8 b1 [2] d6 ac [2] d4 ad [2] cf ab [2] d3 ac [2] cf 83 }

  condition:
    any of them
}
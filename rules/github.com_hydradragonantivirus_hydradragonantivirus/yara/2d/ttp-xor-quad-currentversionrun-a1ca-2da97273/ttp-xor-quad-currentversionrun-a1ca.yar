rule TTP_XOR_QUAD_CurrentVersionRun_a1ca {
  strings:
    $key_a1ca = { f2 a5 [2] d6 ab [2] fd 87 [2] d3 a5 [2] c7 be [2] c8 a4 [2] d6 b9 [2] d4 b8 [2] cf be [2] d3 b9 [2] cf 96 }

  condition:
    any of them
}
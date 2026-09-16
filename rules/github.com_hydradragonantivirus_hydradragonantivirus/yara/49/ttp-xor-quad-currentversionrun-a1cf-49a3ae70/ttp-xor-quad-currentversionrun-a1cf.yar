rule TTP_XOR_QUAD_CurrentVersionRun_a1cf {
  strings:
    $key_a1cf = { f2 a0 [2] d6 ae [2] fd 82 [2] d3 a0 [2] c7 bb [2] c8 a1 [2] d6 bc [2] d4 bd [2] cf bb [2] d3 bc [2] cf 93 }

  condition:
    any of them
}
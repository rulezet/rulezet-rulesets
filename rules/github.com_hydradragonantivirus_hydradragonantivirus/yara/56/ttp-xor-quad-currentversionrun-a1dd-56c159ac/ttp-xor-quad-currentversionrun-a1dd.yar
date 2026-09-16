rule TTP_XOR_QUAD_CurrentVersionRun_a1dd {
  strings:
    $key_a1dd = { f2 b2 [2] d6 bc [2] fd 90 [2] d3 b2 [2] c7 a9 [2] c8 b3 [2] d6 ae [2] d4 af [2] cf a9 [2] d3 ae [2] cf 81 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a1c1 {
  strings:
    $key_a1c1 = { f2 ae [2] d6 a0 [2] fd 8c [2] d3 ae [2] c7 b5 [2] c8 af [2] d6 b2 [2] d4 b3 [2] cf b5 [2] d3 b2 [2] cf 9d }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a1dc {
  strings:
    $key_a1dc = { f2 b3 [2] d6 bd [2] fd 91 [2] d3 b3 [2] c7 a8 [2] c8 b2 [2] d6 af [2] d4 ae [2] cf a8 [2] d3 af [2] cf 80 }

  condition:
    any of them
}
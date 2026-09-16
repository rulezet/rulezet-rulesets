rule TTP_XOR_QUAD_CurrentVersionRun_a6dc {
  strings:
    $key_a6dc = { f5 b3 [2] d1 bd [2] fa 91 [2] d4 b3 [2] c0 a8 [2] cf b2 [2] d1 af [2] d3 ae [2] c8 a8 [2] d4 af [2] c8 80 }

  condition:
    any of them
}
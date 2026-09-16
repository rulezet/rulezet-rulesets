rule TTP_XOR_QUAD_CurrentVersionRun_a6e2 {
  strings:
    $key_a6e2 = { f5 8d [2] d1 83 [2] fa af [2] d4 8d [2] c0 96 [2] cf 8c [2] d1 91 [2] d3 90 [2] c8 96 [2] d4 91 [2] c8 be }

  condition:
    any of them
}
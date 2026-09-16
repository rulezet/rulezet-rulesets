rule TTP_XOR_QUAD_CurrentVersionRun_b7e2 {
  strings:
    $key_b7e2 = { e4 8d [2] c0 83 [2] eb af [2] c5 8d [2] d1 96 [2] de 8c [2] c0 91 [2] c2 90 [2] d9 96 [2] c5 91 [2] d9 be }

  condition:
    any of them
}
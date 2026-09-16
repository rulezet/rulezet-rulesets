rule TTP_XOR_QUAD_CurrentVersionRun_b4e2 {
  strings:
    $key_b4e2 = { e7 8d [2] c3 83 [2] e8 af [2] c6 8d [2] d2 96 [2] dd 8c [2] c3 91 [2] c1 90 [2] da 96 [2] c6 91 [2] da be }

  condition:
    any of them
}
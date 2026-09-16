rule TTP_XOR_QUAD_CurrentVersionRun_b3ce {
  strings:
    $key_b3ce = { e0 a1 [2] c4 af [2] ef 83 [2] c1 a1 [2] d5 ba [2] da a0 [2] c4 bd [2] c6 bc [2] dd ba [2] c1 bd [2] dd 92 }

  condition:
    any of them
}
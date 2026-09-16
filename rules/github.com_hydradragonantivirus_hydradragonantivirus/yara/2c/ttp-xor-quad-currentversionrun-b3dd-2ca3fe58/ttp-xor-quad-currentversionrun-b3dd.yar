rule TTP_XOR_QUAD_CurrentVersionRun_b3dd {
  strings:
    $key_b3dd = { e0 b2 [2] c4 bc [2] ef 90 [2] c1 b2 [2] d5 a9 [2] da b3 [2] c4 ae [2] c6 af [2] dd a9 [2] c1 ae [2] dd 81 }

  condition:
    any of them
}
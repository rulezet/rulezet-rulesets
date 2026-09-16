rule TTP_XOR_QUAD_CurrentVersionRun_b4dc {
  strings:
    $key_b4dc = { e7 b3 [2] c3 bd [2] e8 91 [2] c6 b3 [2] d2 a8 [2] dd b2 [2] c3 af [2] c1 ae [2] da a8 [2] c6 af [2] da 80 }

  condition:
    any of them
}
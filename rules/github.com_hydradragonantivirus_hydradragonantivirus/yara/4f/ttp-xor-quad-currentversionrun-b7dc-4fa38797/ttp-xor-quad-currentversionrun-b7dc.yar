rule TTP_XOR_QUAD_CurrentVersionRun_b7dc {
  strings:
    $key_b7dc = { e4 b3 [2] c0 bd [2] eb 91 [2] c5 b3 [2] d1 a8 [2] de b2 [2] c0 af [2] c2 ae [2] d9 a8 [2] c5 af [2] d9 80 }

  condition:
    any of them
}
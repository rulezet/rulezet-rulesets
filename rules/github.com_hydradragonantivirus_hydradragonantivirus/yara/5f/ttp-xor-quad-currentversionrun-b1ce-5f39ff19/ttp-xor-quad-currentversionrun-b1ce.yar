rule TTP_XOR_QUAD_CurrentVersionRun_b1ce {
  strings:
    $key_b1ce = { e2 a1 [2] c6 af [2] ed 83 [2] c3 a1 [2] d7 ba [2] d8 a0 [2] c6 bd [2] c4 bc [2] df ba [2] c3 bd [2] df 92 }

  condition:
    any of them
}
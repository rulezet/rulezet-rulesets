rule TTP_XOR_QUAD_CurrentVersionRun_b1cf {
  strings:
    $key_b1cf = { e2 a0 [2] c6 ae [2] ed 82 [2] c3 a0 [2] d7 bb [2] d8 a1 [2] c6 bc [2] c4 bd [2] df bb [2] c3 bc [2] df 93 }

  condition:
    any of them
}
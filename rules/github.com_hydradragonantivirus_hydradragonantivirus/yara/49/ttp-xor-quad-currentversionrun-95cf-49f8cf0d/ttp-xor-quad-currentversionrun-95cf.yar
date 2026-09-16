rule TTP_XOR_QUAD_CurrentVersionRun_95cf {
  strings:
    $key_95cf = { c6 a0 [2] e2 ae [2] c9 82 [2] e7 a0 [2] f3 bb [2] fc a1 [2] e2 bc [2] e0 bd [2] fb bb [2] e7 bc [2] fb 93 }

  condition:
    any of them
}
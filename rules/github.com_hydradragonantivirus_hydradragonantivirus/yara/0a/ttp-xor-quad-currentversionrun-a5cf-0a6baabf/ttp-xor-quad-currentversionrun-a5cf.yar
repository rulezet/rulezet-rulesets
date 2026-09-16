rule TTP_XOR_QUAD_CurrentVersionRun_a5cf {
  strings:
    $key_a5cf = { f6 a0 [2] d2 ae [2] f9 82 [2] d7 a0 [2] c3 bb [2] cc a1 [2] d2 bc [2] d0 bd [2] cb bb [2] d7 bc [2] cb 93 }

  condition:
    any of them
}
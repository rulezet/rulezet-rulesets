rule TTP_XOR_QUAD_CurrentVersionRun_8bcf {
  strings:
    $key_8bcf = { d8 a0 [2] fc ae [2] d7 82 [2] f9 a0 [2] ed bb [2] e2 a1 [2] fc bc [2] fe bd [2] e5 bb [2] f9 bc [2] e5 93 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9599 {
  strings:
    $key_9599 = { c6 f6 [2] e2 f8 [2] c9 d4 [2] e7 f6 [2] f3 ed [2] fc f7 [2] e2 ea [2] e0 eb [2] fb ed [2] e7 ea [2] fb c5 }

  condition:
    any of them
}
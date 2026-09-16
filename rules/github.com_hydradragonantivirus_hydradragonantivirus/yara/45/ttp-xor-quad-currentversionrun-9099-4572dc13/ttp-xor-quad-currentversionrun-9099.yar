rule TTP_XOR_QUAD_CurrentVersionRun_9099 {
  strings:
    $key_9099 = { c3 f6 [2] e7 f8 [2] cc d4 [2] e2 f6 [2] f6 ed [2] f9 f7 [2] e7 ea [2] e5 eb [2] fe ed [2] e2 ea [2] fe c5 }

  condition:
    any of them
}
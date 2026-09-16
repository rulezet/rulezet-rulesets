rule TTP_XOR_QUAD_CurrentVersionRun_8c9f {
  strings:
    $key_8c9f = { df f0 [2] fb fe [2] d0 d2 [2] fe f0 [2] ea eb [2] e5 f1 [2] fb ec [2] f9 ed [2] e2 eb [2] fe ec [2] e2 c3 }

  condition:
    any of them
}
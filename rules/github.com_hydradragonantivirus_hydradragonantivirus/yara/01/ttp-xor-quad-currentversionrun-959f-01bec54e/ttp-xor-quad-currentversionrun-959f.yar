rule TTP_XOR_QUAD_CurrentVersionRun_959f {
  strings:
    $key_959f = { c6 f0 [2] e2 fe [2] c9 d2 [2] e7 f0 [2] f3 eb [2] fc f1 [2] e2 ec [2] e0 ed [2] fb eb [2] e7 ec [2] fb c3 }

  condition:
    any of them
}
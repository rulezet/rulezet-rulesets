rule TTP_XOR_QUAD_CurrentVersionRun_b299 {
  strings:
    $key_b299 = { e1 f6 [2] c5 f8 [2] ee d4 [2] c0 f6 [2] d4 ed [2] db f7 [2] c5 ea [2] c7 eb [2] dc ed [2] c0 ea [2] dc c5 }

  condition:
    any of them
}
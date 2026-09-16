rule TTP_XOR_QUAD_CurrentVersionRun_b599 {
  strings:
    $key_b599 = { e6 f6 [2] c2 f8 [2] e9 d4 [2] c7 f6 [2] d3 ed [2] dc f7 [2] c2 ea [2] c0 eb [2] db ed [2] c7 ea [2] db c5 }

  condition:
    any of them
}
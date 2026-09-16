rule TTP_XOR_QUAD_CurrentVersionRun_b585 {
  strings:
    $key_b585 = { e6 ea [2] c2 e4 [2] e9 c8 [2] c7 ea [2] d3 f1 [2] dc eb [2] c2 f6 [2] c0 f7 [2] db f1 [2] c7 f6 [2] db d9 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_b298 {
  strings:
    $key_b298 = { e1 f7 [2] c5 f9 [2] ee d5 [2] c0 f7 [2] d4 ec [2] db f6 [2] c5 eb [2] c7 ea [2] dc ec [2] c0 eb [2] dc c4 }

  condition:
    any of them
}
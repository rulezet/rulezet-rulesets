rule TTP_XOR_QUAD_CurrentVersionRun_b582 {
  strings:
    $key_b582 = { e6 ed [2] c2 e3 [2] e9 cf [2] c7 ed [2] d3 f6 [2] dc ec [2] c2 f1 [2] c0 f0 [2] db f6 [2] c7 f1 [2] db de }

  condition:
    any of them
}
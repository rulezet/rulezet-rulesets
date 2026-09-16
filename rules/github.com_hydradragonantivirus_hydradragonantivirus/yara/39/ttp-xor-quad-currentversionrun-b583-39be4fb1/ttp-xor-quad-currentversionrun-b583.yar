rule TTP_XOR_QUAD_CurrentVersionRun_b583 {
  strings:
    $key_b583 = { e6 ec [2] c2 e2 [2] e9 ce [2] c7 ec [2] d3 f7 [2] dc ed [2] c2 f0 [2] c0 f1 [2] db f7 [2] c7 f0 [2] db df }

  condition:
    any of them
}
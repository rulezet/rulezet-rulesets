rule TTP_XOR_QUAD_CurrentVersionRun_a983 {
  strings:
    $key_a983 = { fa ec [2] de e2 [2] f5 ce [2] db ec [2] cf f7 [2] c0 ed [2] de f0 [2] dc f1 [2] c7 f7 [2] db f0 [2] c7 df }

  condition:
    any of them
}
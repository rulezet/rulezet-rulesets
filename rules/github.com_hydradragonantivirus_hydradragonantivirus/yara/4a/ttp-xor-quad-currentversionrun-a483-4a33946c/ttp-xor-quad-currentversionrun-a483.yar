rule TTP_XOR_QUAD_CurrentVersionRun_a483 {
  strings:
    $key_a483 = { f7 ec [2] d3 e2 [2] f8 ce [2] d6 ec [2] c2 f7 [2] cd ed [2] d3 f0 [2] d1 f1 [2] ca f7 [2] d6 f0 [2] ca df }

  condition:
    any of them
}
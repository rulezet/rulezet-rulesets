rule TTP_XOR_QUAD_CurrentVersionRun_a491 {
  strings:
    $key_a491 = { f7 fe [2] d3 f0 [2] f8 dc [2] d6 fe [2] c2 e5 [2] cd ff [2] d3 e2 [2] d1 e3 [2] ca e5 [2] d6 e2 [2] ca cd }

  condition:
    any of them
}
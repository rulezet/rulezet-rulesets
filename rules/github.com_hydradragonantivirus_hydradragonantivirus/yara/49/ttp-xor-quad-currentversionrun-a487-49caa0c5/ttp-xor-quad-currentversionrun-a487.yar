rule TTP_XOR_QUAD_CurrentVersionRun_a487 {
  strings:
    $key_a487 = { f7 e8 [2] d3 e6 [2] f8 ca [2] d6 e8 [2] c2 f3 [2] cd e9 [2] d3 f4 [2] d1 f5 [2] ca f3 [2] d6 f4 [2] ca db }

  condition:
    any of them
}
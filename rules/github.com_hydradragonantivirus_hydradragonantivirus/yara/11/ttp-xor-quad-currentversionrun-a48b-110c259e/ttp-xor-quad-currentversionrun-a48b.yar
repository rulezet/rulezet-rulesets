rule TTP_XOR_QUAD_CurrentVersionRun_a48b {
  strings:
    $key_a48b = { f7 e4 [2] d3 ea [2] f8 c6 [2] d6 e4 [2] c2 ff [2] cd e5 [2] d3 f8 [2] d1 f9 [2] ca ff [2] d6 f8 [2] ca d7 }

  condition:
    any of them
}
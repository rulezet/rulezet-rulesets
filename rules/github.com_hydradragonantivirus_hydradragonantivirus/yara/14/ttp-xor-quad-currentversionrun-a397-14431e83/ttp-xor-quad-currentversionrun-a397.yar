rule TTP_XOR_QUAD_CurrentVersionRun_a397 {
  strings:
    $key_a397 = { f0 f8 [2] d4 f6 [2] ff da [2] d1 f8 [2] c5 e3 [2] ca f9 [2] d4 e4 [2] d6 e5 [2] cd e3 [2] d1 e4 [2] cd cb }

  condition:
    any of them
}
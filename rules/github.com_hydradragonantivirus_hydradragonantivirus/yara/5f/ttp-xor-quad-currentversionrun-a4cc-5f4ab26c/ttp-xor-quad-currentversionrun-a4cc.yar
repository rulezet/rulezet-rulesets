rule TTP_XOR_QUAD_CurrentVersionRun_a4cc {
  strings:
    $key_a4cc = { f7 a3 [2] d3 ad [2] f8 81 [2] d6 a3 [2] c2 b8 [2] cd a2 [2] d3 bf [2] d1 be [2] ca b8 [2] d6 bf [2] ca 90 }

  condition:
    any of them
}
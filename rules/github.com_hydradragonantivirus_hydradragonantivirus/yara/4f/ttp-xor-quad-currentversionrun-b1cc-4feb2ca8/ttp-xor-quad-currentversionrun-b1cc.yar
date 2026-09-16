rule TTP_XOR_QUAD_CurrentVersionRun_b1cc {
  strings:
    $key_b1cc = { e2 a3 [2] c6 ad [2] ed 81 [2] c3 a3 [2] d7 b8 [2] d8 a2 [2] c6 bf [2] c4 be [2] df b8 [2] c3 bf [2] df 90 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a3cc {
  strings:
    $key_a3cc = { f0 a3 [2] d4 ad [2] ff 81 [2] d1 a3 [2] c5 b8 [2] ca a2 [2] d4 bf [2] d6 be [2] cd b8 [2] d1 bf [2] cd 90 }

  condition:
    any of them
}
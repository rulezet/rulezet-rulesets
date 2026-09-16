rule TTP_XOR_QUAD_CurrentVersionRun_a5cc {
  strings:
    $key_a5cc = { f6 a3 [2] d2 ad [2] f9 81 [2] d7 a3 [2] c3 b8 [2] cc a2 [2] d2 bf [2] d0 be [2] cb b8 [2] d7 bf [2] cb 90 }

  condition:
    any of them
}
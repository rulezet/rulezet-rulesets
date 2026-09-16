rule TTP_XOR_QUAD_CurrentVersionRun_b2cc {
  strings:
    $key_b2cc = { e1 a3 [2] c5 ad [2] ee 81 [2] c0 a3 [2] d4 b8 [2] db a2 [2] c5 bf [2] c7 be [2] dc b8 [2] c0 bf [2] dc 90 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_95cc {
  strings:
    $key_95cc = { c6 a3 [2] e2 ad [2] c9 81 [2] e7 a3 [2] f3 b8 [2] fc a2 [2] e2 bf [2] e0 be [2] fb b8 [2] e7 bf [2] fb 90 }

  condition:
    any of them
}
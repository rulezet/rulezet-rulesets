rule TTP_XOR_QUAD_CurrentVersionRun_73cc {
  strings:
    $key_73cc = { 20 a3 [2] 04 ad [2] 2f 81 [2] 01 a3 [2] 15 b8 [2] 1a a2 [2] 04 bf [2] 06 be [2] 1d b8 [2] 01 bf [2] 1d 90 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_42cc {
  strings:
    $key_42cc = { 11 a3 [2] 35 ad [2] 1e 81 [2] 30 a3 [2] 24 b8 [2] 2b a2 [2] 35 bf [2] 37 be [2] 2c b8 [2] 30 bf [2] 2c 90 }

  condition:
    any of them
}
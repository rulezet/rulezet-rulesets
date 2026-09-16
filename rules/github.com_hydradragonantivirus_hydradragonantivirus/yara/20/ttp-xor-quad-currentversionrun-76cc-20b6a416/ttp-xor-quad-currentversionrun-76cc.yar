rule TTP_XOR_QUAD_CurrentVersionRun_76cc {
  strings:
    $key_76cc = { 25 a3 [2] 01 ad [2] 2a 81 [2] 04 a3 [2] 10 b8 [2] 1f a2 [2] 01 bf [2] 03 be [2] 18 b8 [2] 04 bf [2] 18 90 }

  condition:
    any of them
}
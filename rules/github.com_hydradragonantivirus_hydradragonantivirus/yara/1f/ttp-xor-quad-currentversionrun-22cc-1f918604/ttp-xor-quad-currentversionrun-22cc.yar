rule TTP_XOR_QUAD_CurrentVersionRun_22cc {
  strings:
    $key_22cc = { 71 a3 [2] 55 ad [2] 7e 81 [2] 50 a3 [2] 44 b8 [2] 4b a2 [2] 55 bf [2] 57 be [2] 4c b8 [2] 50 bf [2] 4c 90 }

  condition:
    any of them
}
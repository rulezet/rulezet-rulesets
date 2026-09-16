rule TTP_XOR_QUAD_CurrentVersionRun_06cc {
  strings:
    $key_06cc = { 55 a3 [2] 71 ad [2] 5a 81 [2] 74 a3 [2] 60 b8 [2] 6f a2 [2] 71 bf [2] 73 be [2] 68 b8 [2] 74 bf [2] 68 90 }

  condition:
    any of them
}
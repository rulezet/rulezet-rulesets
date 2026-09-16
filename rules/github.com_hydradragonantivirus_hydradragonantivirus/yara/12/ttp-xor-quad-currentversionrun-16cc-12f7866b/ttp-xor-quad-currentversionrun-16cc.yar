rule TTP_XOR_QUAD_CurrentVersionRun_16cc {
  strings:
    $key_16cc = { 45 a3 [2] 61 ad [2] 4a 81 [2] 64 a3 [2] 70 b8 [2] 7f a2 [2] 61 bf [2] 63 be [2] 78 b8 [2] 64 bf [2] 78 90 }

  condition:
    any of them
}
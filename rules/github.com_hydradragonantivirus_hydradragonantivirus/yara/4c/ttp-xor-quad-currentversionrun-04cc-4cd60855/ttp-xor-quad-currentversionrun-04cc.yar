rule TTP_XOR_QUAD_CurrentVersionRun_04cc {
  strings:
    $key_04cc = { 57 a3 [2] 73 ad [2] 58 81 [2] 76 a3 [2] 62 b8 [2] 6d a2 [2] 73 bf [2] 71 be [2] 6a b8 [2] 76 bf [2] 6a 90 }

  condition:
    any of them
}
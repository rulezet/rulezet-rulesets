rule TTP_XOR_QUAD_CurrentVersionRun_07cc {
  strings:
    $key_07cc = { 54 a3 [2] 70 ad [2] 5b 81 [2] 75 a3 [2] 61 b8 [2] 6e a2 [2] 70 bf [2] 72 be [2] 69 b8 [2] 75 bf [2] 69 90 }

  condition:
    any of them
}
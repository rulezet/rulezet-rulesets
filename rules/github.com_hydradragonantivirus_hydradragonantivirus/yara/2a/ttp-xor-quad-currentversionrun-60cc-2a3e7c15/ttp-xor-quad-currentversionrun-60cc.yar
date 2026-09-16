rule TTP_XOR_QUAD_CurrentVersionRun_60cc {
  strings:
    $key_60cc = { 33 a3 [2] 17 ad [2] 3c 81 [2] 12 a3 [2] 06 b8 [2] 09 a2 [2] 17 bf [2] 15 be [2] 0e b8 [2] 12 bf [2] 0e 90 }

  condition:
    any of them
}
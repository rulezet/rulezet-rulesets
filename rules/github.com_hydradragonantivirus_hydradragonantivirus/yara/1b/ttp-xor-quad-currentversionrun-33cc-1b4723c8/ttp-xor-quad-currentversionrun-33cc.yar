rule TTP_XOR_QUAD_CurrentVersionRun_33cc {
  strings:
    $key_33cc = { 60 a3 [2] 44 ad [2] 6f 81 [2] 41 a3 [2] 55 b8 [2] 5a a2 [2] 44 bf [2] 46 be [2] 5d b8 [2] 41 bf [2] 5d 90 }

  condition:
    any of them
}
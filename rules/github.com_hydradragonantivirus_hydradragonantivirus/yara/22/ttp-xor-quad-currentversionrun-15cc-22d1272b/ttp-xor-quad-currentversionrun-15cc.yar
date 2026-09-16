rule TTP_XOR_QUAD_CurrentVersionRun_15cc {
  strings:
    $key_15cc = { 46 a3 [2] 62 ad [2] 49 81 [2] 67 a3 [2] 73 b8 [2] 7c a2 [2] 62 bf [2] 60 be [2] 7b b8 [2] 67 bf [2] 7b 90 }

  condition:
    any of them
}
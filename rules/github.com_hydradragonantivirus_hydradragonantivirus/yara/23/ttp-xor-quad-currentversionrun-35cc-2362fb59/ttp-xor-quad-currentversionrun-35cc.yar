rule TTP_XOR_QUAD_CurrentVersionRun_35cc {
  strings:
    $key_35cc = { 66 a3 [2] 42 ad [2] 69 81 [2] 47 a3 [2] 53 b8 [2] 5c a2 [2] 42 bf [2] 40 be [2] 5b b8 [2] 47 bf [2] 5b 90 }

  condition:
    any of them
}
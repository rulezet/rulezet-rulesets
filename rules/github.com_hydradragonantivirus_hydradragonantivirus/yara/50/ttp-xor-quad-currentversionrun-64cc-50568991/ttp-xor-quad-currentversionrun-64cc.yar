rule TTP_XOR_QUAD_CurrentVersionRun_64cc {
  strings:
    $key_64cc = { 37 a3 [2] 13 ad [2] 38 81 [2] 16 a3 [2] 02 b8 [2] 0d a2 [2] 13 bf [2] 11 be [2] 0a b8 [2] 16 bf [2] 0a 90 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_24cc {
  strings:
    $key_24cc = { 77 a3 [2] 53 ad [2] 78 81 [2] 56 a3 [2] 42 b8 [2] 4d a2 [2] 53 bf [2] 51 be [2] 4a b8 [2] 56 bf [2] 4a 90 }

  condition:
    any of them
}
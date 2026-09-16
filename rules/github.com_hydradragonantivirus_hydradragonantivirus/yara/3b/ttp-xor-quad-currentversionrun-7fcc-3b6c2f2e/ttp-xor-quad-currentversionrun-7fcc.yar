rule TTP_XOR_QUAD_CurrentVersionRun_7fcc {
  strings:
    $key_7fcc = { 2c a3 [2] 08 ad [2] 23 81 [2] 0d a3 [2] 19 b8 [2] 16 a2 [2] 08 bf [2] 0a be [2] 11 b8 [2] 0d bf [2] 11 90 }

  condition:
    any of them
}
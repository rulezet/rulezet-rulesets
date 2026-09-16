rule TTP_XOR_QUAD_CurrentVersionRun_4fcc {
  strings:
    $key_4fcc = { 1c a3 [2] 38 ad [2] 13 81 [2] 3d a3 [2] 29 b8 [2] 26 a2 [2] 38 bf [2] 3a be [2] 21 b8 [2] 3d bf [2] 21 90 }

  condition:
    any of them
}
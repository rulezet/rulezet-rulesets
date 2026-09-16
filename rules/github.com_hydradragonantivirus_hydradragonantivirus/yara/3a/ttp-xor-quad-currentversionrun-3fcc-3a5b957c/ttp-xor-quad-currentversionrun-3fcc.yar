rule TTP_XOR_QUAD_CurrentVersionRun_3fcc {
  strings:
    $key_3fcc = { 6c a3 [2] 48 ad [2] 63 81 [2] 4d a3 [2] 59 b8 [2] 56 a2 [2] 48 bf [2] 4a be [2] 51 b8 [2] 4d bf [2] 51 90 }

  condition:
    any of them
}
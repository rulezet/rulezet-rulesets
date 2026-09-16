rule TTP_XOR_QUAD_CurrentVersionRun_efcc {
  strings:
    $key_efcc = { bc a3 [2] 98 ad [2] b3 81 [2] 9d a3 [2] 89 b8 [2] 86 a2 [2] 98 bf [2] 9a be [2] 81 b8 [2] 9d bf [2] 81 90 }

  condition:
    any of them
}
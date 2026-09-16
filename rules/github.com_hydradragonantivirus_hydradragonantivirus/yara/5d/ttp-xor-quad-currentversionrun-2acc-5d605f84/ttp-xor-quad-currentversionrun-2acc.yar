rule TTP_XOR_QUAD_CurrentVersionRun_2acc {
  strings:
    $key_2acc = { 79 a3 [2] 5d ad [2] 76 81 [2] 58 a3 [2] 4c b8 [2] 43 a2 [2] 5d bf [2] 5f be [2] 44 b8 [2] 58 bf [2] 44 90 }

  condition:
    any of them
}
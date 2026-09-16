rule TTP_XOR_QUAD_CurrentVersionRun_1acc {
  strings:
    $key_1acc = { 49 a3 [2] 6d ad [2] 46 81 [2] 68 a3 [2] 7c b8 [2] 73 a2 [2] 6d bf [2] 6f be [2] 74 b8 [2] 68 bf [2] 74 90 }

  condition:
    any of them
}
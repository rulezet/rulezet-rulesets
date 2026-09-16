rule TTP_XOR_QUAD_CurrentVersionRun_7acc {
  strings:
    $key_7acc = { 29 a3 [2] 0d ad [2] 26 81 [2] 08 a3 [2] 1c b8 [2] 13 a2 [2] 0d bf [2] 0f be [2] 14 b8 [2] 08 bf [2] 14 90 }

  condition:
    any of them
}
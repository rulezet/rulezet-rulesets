rule TTP_XOR_QUAD_CurrentVersionRun_3acc {
  strings:
    $key_3acc = { 69 a3 [2] 4d ad [2] 66 81 [2] 48 a3 [2] 5c b8 [2] 53 a2 [2] 4d bf [2] 4f be [2] 54 b8 [2] 48 bf [2] 54 90 }

  condition:
    any of them
}
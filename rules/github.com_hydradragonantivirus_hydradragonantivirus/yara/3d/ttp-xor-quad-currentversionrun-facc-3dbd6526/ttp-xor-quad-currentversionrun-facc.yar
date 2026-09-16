rule TTP_XOR_QUAD_CurrentVersionRun_facc {
  strings:
    $key_facc = { a9 a3 [2] 8d ad [2] a6 81 [2] 88 a3 [2] 9c b8 [2] 93 a2 [2] 8d bf [2] 8f be [2] 94 b8 [2] 88 bf [2] 94 90 }

  condition:
    any of them
}
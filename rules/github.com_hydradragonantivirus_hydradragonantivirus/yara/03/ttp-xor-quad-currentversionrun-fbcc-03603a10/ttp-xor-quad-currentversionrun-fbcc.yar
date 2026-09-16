rule TTP_XOR_QUAD_CurrentVersionRun_fbcc {
  strings:
    $key_fbcc = { a8 a3 [2] 8c ad [2] a7 81 [2] 89 a3 [2] 9d b8 [2] 92 a2 [2] 8c bf [2] 8e be [2] 95 b8 [2] 89 bf [2] 95 90 }

  condition:
    any of them
}
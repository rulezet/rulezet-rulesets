rule TTP_XOR_QUAD_CurrentVersionRun_1bcc {
  strings:
    $key_1bcc = { 48 a3 [2] 6c ad [2] 47 81 [2] 69 a3 [2] 7d b8 [2] 72 a2 [2] 6c bf [2] 6e be [2] 75 b8 [2] 69 bf [2] 75 90 }

  condition:
    any of them
}
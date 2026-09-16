rule TTP_XOR_QUAD_CurrentVersionRun_7bcc {
  strings:
    $key_7bcc = { 28 a3 [2] 0c ad [2] 27 81 [2] 09 a3 [2] 1d b8 [2] 12 a2 [2] 0c bf [2] 0e be [2] 15 b8 [2] 09 bf [2] 15 90 }

  condition:
    any of them
}
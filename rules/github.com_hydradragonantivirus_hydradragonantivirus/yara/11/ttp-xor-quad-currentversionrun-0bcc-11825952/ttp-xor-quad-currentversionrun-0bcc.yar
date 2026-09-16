rule TTP_XOR_QUAD_CurrentVersionRun_0bcc {
  strings:
    $key_0bcc = { 58 a3 [2] 7c ad [2] 57 81 [2] 79 a3 [2] 6d b8 [2] 62 a2 [2] 7c bf [2] 7e be [2] 65 b8 [2] 79 bf [2] 65 90 }

  condition:
    any of them
}
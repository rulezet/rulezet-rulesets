rule TTP_XOR_QUAD_CurrentVersionRun_3bcc {
  strings:
    $key_3bcc = { 68 a3 [2] 4c ad [2] 67 81 [2] 49 a3 [2] 5d b8 [2] 52 a2 [2] 4c bf [2] 4e be [2] 55 b8 [2] 49 bf [2] 55 90 }

  condition:
    any of them
}
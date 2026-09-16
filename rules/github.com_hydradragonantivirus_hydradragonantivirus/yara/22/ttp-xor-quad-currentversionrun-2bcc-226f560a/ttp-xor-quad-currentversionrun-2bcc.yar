rule TTP_XOR_QUAD_CurrentVersionRun_2bcc {
  strings:
    $key_2bcc = { 78 a3 [2] 5c ad [2] 77 81 [2] 59 a3 [2] 4d b8 [2] 42 a2 [2] 5c bf [2] 5e be [2] 45 b8 [2] 59 bf [2] 45 90 }

  condition:
    any of them
}
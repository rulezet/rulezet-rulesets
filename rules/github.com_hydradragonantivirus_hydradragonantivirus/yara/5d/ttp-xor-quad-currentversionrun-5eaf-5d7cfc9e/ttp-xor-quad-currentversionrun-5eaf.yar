rule TTP_XOR_QUAD_CurrentVersionRun_5eaf {
  strings:
    $key_5eaf = { 0d c0 [2] 29 ce [2] 02 e2 [2] 2c c0 [2] 38 db [2] 37 c1 [2] 29 dc [2] 2b dd [2] 30 db [2] 2c dc [2] 30 f3 }

  condition:
    any of them
}
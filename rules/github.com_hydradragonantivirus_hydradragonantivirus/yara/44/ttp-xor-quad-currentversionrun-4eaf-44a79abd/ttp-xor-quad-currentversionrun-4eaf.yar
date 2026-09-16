rule TTP_XOR_QUAD_CurrentVersionRun_4eaf {
  strings:
    $key_4eaf = { 1d c0 [2] 39 ce [2] 12 e2 [2] 3c c0 [2] 28 db [2] 27 c1 [2] 39 dc [2] 3b dd [2] 20 db [2] 3c dc [2] 20 f3 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_3eaf {
  strings:
    $key_3eaf = { 6d c0 [2] 49 ce [2] 62 e2 [2] 4c c0 [2] 58 db [2] 57 c1 [2] 49 dc [2] 4b dd [2] 50 db [2] 4c dc [2] 50 f3 }

  condition:
    any of them
}
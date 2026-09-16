rule TTP_XOR_QUAD_CurrentVersionRun_5faf {
  strings:
    $key_5faf = { 0c c0 [2] 28 ce [2] 03 e2 [2] 2d c0 [2] 39 db [2] 36 c1 [2] 28 dc [2] 2a dd [2] 31 db [2] 2d dc [2] 31 f3 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2faf {
  strings:
    $key_2faf = { 7c c0 [2] 58 ce [2] 73 e2 [2] 5d c0 [2] 49 db [2] 46 c1 [2] 58 dc [2] 5a dd [2] 41 db [2] 5d dc [2] 41 f3 }

  condition:
    any of them
}
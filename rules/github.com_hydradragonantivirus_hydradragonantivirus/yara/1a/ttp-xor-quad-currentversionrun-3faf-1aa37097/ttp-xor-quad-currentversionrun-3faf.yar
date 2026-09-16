rule TTP_XOR_QUAD_CurrentVersionRun_3faf {
  strings:
    $key_3faf = { 6c c0 [2] 48 ce [2] 63 e2 [2] 4d c0 [2] 59 db [2] 56 c1 [2] 48 dc [2] 4a dd [2] 51 db [2] 4d dc [2] 51 f3 }

  condition:
    any of them
}
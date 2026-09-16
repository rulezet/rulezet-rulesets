rule TTP_XOR_QUAD_CurrentVersionRun_13af {
  strings:
    $key_13af = { 40 c0 [2] 64 ce [2] 4f e2 [2] 61 c0 [2] 75 db [2] 7a c1 [2] 64 dc [2] 66 dd [2] 7d db [2] 61 dc [2] 7d f3 }

  condition:
    any of them
}
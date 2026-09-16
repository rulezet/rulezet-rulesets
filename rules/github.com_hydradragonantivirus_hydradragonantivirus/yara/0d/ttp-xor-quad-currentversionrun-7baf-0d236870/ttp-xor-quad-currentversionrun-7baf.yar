rule TTP_XOR_QUAD_CurrentVersionRun_7baf {
  strings:
    $key_7baf = { 28 c0 [2] 0c ce [2] 27 e2 [2] 09 c0 [2] 1d db [2] 12 c1 [2] 0c dc [2] 0e dd [2] 15 db [2] 09 dc [2] 15 f3 }

  condition:
    any of them
}
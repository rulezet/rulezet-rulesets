rule TTP_XOR_QUAD_CurrentVersionRun_1baf {
  strings:
    $key_1baf = { 48 c0 [2] 6c ce [2] 47 e2 [2] 69 c0 [2] 7d db [2] 72 c1 [2] 6c dc [2] 6e dd [2] 75 db [2] 69 dc [2] 75 f3 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_6baf {
  strings:
    $key_6baf = { 38 c0 [2] 1c ce [2] 37 e2 [2] 19 c0 [2] 0d db [2] 02 c1 [2] 1c dc [2] 1e dd [2] 05 db [2] 19 dc [2] 05 f3 }

  condition:
    any of them
}
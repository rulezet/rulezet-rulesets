rule TTP_XOR_QUAD_CurrentVersionRun_5baf {
  strings:
    $key_5baf = { 08 c0 [2] 2c ce [2] 07 e2 [2] 29 c0 [2] 3d db [2] 32 c1 [2] 2c dc [2] 2e dd [2] 35 db [2] 29 dc [2] 35 f3 }

  condition:
    any of them
}
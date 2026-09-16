rule TTP_XOR_QUAD_CurrentVersionRun_2baf {
  strings:
    $key_2baf = { 78 c0 [2] 5c ce [2] 77 e2 [2] 59 c0 [2] 4d db [2] 42 c1 [2] 5c dc [2] 5e dd [2] 45 db [2] 59 dc [2] 45 f3 }

  condition:
    any of them
}
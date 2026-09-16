rule TTP_XOR_QUAD_CurrentVersionRun_ebaf {
  strings:
    $key_ebaf = { b8 c0 [2] 9c ce [2] b7 e2 [2] 99 c0 [2] 8d db [2] 82 c1 [2] 9c dc [2] 9e dd [2] 85 db [2] 99 dc [2] 85 f3 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_93af {
  strings:
    $key_93af = { c0 c0 [2] e4 ce [2] cf e2 [2] e1 c0 [2] f5 db [2] fa c1 [2] e4 dc [2] e6 dd [2] fd db [2] e1 dc [2] fd f3 }

  condition:
    any of them
}
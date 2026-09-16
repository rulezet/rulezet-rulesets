rule TTP_XOR_QUAD_CurrentVersionRun_97af {
  strings:
    $key_97af = { c4 c0 [2] e0 ce [2] cb e2 [2] e5 c0 [2] f1 db [2] fe c1 [2] e0 dc [2] e2 dd [2] f9 db [2] e5 dc [2] f9 f3 }

  condition:
    any of them
}
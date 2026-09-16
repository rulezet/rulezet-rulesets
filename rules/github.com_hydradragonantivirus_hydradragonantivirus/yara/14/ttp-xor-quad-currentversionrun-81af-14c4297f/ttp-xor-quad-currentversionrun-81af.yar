rule TTP_XOR_QUAD_CurrentVersionRun_81af {
  strings:
    $key_81af = { d2 c0 [2] f6 ce [2] dd e2 [2] f3 c0 [2] e7 db [2] e8 c1 [2] f6 dc [2] f4 dd [2] ef db [2] f3 dc [2] ef f3 }

  condition:
    any of them
}
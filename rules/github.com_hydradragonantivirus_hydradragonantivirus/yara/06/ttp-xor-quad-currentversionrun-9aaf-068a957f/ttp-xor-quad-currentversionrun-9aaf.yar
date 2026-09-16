rule TTP_XOR_QUAD_CurrentVersionRun_9aaf {
  strings:
    $key_9aaf = { c9 c0 [2] ed ce [2] c6 e2 [2] e8 c0 [2] fc db [2] f3 c1 [2] ed dc [2] ef dd [2] f4 db [2] e8 dc [2] f4 f3 }

  condition:
    any of them
}
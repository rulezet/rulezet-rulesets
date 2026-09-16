rule TTP_XOR_QUAD_CurrentVersionRun_82af {
  strings:
    $key_82af = { d1 c0 [2] f5 ce [2] de e2 [2] f0 c0 [2] e4 db [2] eb c1 [2] f5 dc [2] f7 dd [2] ec db [2] f0 dc [2] ec f3 }

  condition:
    any of them
}
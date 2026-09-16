rule TTP_XOR_QUAD_CurrentVersionRun_9baf {
  strings:
    $key_9baf = { c8 c0 [2] ec ce [2] c7 e2 [2] e9 c0 [2] fd db [2] f2 c1 [2] ec dc [2] ee dd [2] f5 db [2] e9 dc [2] f5 f3 }

  condition:
    any of them
}
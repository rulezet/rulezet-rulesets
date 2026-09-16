rule TTP_XOR_QUAD_CurrentVersionRun_9b9c {
  strings:
    $key_9b9c = { c8 f3 [2] ec fd [2] c7 d1 [2] e9 f3 [2] fd e8 [2] f2 f2 [2] ec ef [2] ee ee [2] f5 e8 [2] e9 ef [2] f5 c0 }

  condition:
    any of them
}
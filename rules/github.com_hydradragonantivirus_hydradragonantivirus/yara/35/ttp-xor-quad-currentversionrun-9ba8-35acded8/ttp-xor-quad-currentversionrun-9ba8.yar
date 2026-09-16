rule TTP_XOR_QUAD_CurrentVersionRun_9ba8 {
  strings:
    $key_9ba8 = { c8 c7 [2] ec c9 [2] c7 e5 [2] e9 c7 [2] fd dc [2] f2 c6 [2] ec db [2] ee da [2] f5 dc [2] e9 db [2] f5 f4 }

  condition:
    any of them
}
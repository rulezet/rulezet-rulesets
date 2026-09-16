rule TTP_XOR_QUAD_CurrentVersionRun_9b97 {
  strings:
    $key_9b97 = { c8 f8 [2] ec f6 [2] c7 da [2] e9 f8 [2] fd e3 [2] f2 f9 [2] ec e4 [2] ee e5 [2] f5 e3 [2] e9 e4 [2] f5 cb }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9b87 {
  strings:
    $key_9b87 = { c8 e8 [2] ec e6 [2] c7 ca [2] e9 e8 [2] fd f3 [2] f2 e9 [2] ec f4 [2] ee f5 [2] f5 f3 [2] e9 f4 [2] f5 db }

  condition:
    any of them
}
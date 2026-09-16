rule TTP_XOR_QUAD_CurrentVersionRun_9b80 {
  strings:
    $key_9b80 = { c8 ef [2] ec e1 [2] c7 cd [2] e9 ef [2] fd f4 [2] f2 ee [2] ec f3 [2] ee f2 [2] f5 f4 [2] e9 f3 [2] f5 dc }

  condition:
    any of them
}
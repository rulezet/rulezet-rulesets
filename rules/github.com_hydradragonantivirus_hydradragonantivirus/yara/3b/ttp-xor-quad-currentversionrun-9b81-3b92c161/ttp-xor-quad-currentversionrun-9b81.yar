rule TTP_XOR_QUAD_CurrentVersionRun_9b81 {
  strings:
    $key_9b81 = { c8 ee [2] ec e0 [2] c7 cc [2] e9 ee [2] fd f5 [2] f2 ef [2] ec f2 [2] ee f3 [2] f5 f5 [2] e9 f2 [2] f5 dd }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9381 {
  strings:
    $key_9381 = { c0 ee [2] e4 e0 [2] cf cc [2] e1 ee [2] f5 f5 [2] fa ef [2] e4 f2 [2] e6 f3 [2] fd f5 [2] e1 f2 [2] fd dd }

  condition:
    any of them
}
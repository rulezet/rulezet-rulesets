rule TTP_XOR_QUAD_CurrentVersionRun_9b84 {
  strings:
    $key_9b84 = { c8 eb [2] ec e5 [2] c7 c9 [2] e9 eb [2] fd f0 [2] f2 ea [2] ec f7 [2] ee f6 [2] f5 f0 [2] e9 f7 [2] f5 d8 }

  condition:
    any of them
}
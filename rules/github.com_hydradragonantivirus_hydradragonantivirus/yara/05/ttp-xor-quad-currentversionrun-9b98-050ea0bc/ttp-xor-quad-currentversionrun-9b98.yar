rule TTP_XOR_QUAD_CurrentVersionRun_9b98 {
  strings:
    $key_9b98 = { c8 f7 [2] ec f9 [2] c7 d5 [2] e9 f7 [2] fd ec [2] f2 f6 [2] ec eb [2] ee ea [2] f5 ec [2] e9 eb [2] f5 c4 }

  condition:
    any of them
}
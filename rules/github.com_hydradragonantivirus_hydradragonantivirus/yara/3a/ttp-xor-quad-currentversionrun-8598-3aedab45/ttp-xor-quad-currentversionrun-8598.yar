rule TTP_XOR_QUAD_CurrentVersionRun_8598 {
  strings:
    $key_8598 = { d6 f7 [2] f2 f9 [2] d9 d5 [2] f7 f7 [2] e3 ec [2] ec f6 [2] f2 eb [2] f0 ea [2] eb ec [2] f7 eb [2] eb c4 }

  condition:
    any of them
}
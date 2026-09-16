rule TTP_XOR_QUAD_CurrentVersionRun_9b8b {
  strings:
    $key_9b8b = { c8 e4 [2] ec ea [2] c7 c6 [2] e9 e4 [2] fd ff [2] f2 e5 [2] ec f8 [2] ee f9 [2] f5 ff [2] e9 f8 [2] f5 d7 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9b8a {
  strings:
    $key_9b8a = { c8 e5 [2] ec eb [2] c7 c7 [2] e9 e5 [2] fd fe [2] f2 e4 [2] ec f9 [2] ee f8 [2] f5 fe [2] e9 f9 [2] f5 d6 }

  condition:
    any of them
}
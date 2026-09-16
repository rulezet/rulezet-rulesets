rule TTP_XOR_QUAD_CurrentVersionRun_9b93 {
  strings:
    $key_9b93 = { c8 fc [2] ec f2 [2] c7 de [2] e9 fc [2] fd e7 [2] f2 fd [2] ec e0 [2] ee e1 [2] f5 e7 [2] e9 e0 [2] f5 cf }

  condition:
    any of them
}
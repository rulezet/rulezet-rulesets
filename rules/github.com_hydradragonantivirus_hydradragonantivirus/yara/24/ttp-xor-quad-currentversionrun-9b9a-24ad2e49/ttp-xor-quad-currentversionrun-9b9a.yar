rule TTP_XOR_QUAD_CurrentVersionRun_9b9a {
  strings:
    $key_9b9a = { c8 f5 [2] ec fb [2] c7 d7 [2] e9 f5 [2] fd ee [2] f2 f4 [2] ec e9 [2] ee e8 [2] f5 ee [2] e9 e9 [2] f5 c6 }

  condition:
    any of them
}
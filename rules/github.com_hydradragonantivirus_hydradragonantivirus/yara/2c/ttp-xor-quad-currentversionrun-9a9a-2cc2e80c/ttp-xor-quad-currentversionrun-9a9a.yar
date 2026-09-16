rule TTP_XOR_QUAD_CurrentVersionRun_9a9a {
  strings:
    $key_9a9a = { c9 f5 [2] ed fb [2] c6 d7 [2] e8 f5 [2] fc ee [2] f3 f4 [2] ed e9 [2] ef e8 [2] f4 ee [2] e8 e9 [2] f4 c6 }

  condition:
    any of them
}
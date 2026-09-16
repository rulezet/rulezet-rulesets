rule TTP_XOR_QUAD_CurrentVersionRun_959a {
  strings:
    $key_959a = { c6 f5 [2] e2 fb [2] c9 d7 [2] e7 f5 [2] f3 ee [2] fc f4 [2] e2 e9 [2] e0 e8 [2] fb ee [2] e7 e9 [2] fb c6 }

  condition:
    any of them
}
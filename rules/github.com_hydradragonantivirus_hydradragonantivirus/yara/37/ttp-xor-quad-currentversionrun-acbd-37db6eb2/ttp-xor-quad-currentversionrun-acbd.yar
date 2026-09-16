rule TTP_XOR_QUAD_CurrentVersionRun_acbd {
  strings:
    $key_acbd = { ff d2 [2] db dc [2] f0 f0 [2] de d2 [2] ca c9 [2] c5 d3 [2] db ce [2] d9 cf [2] c2 c9 [2] de ce [2] c2 e1 }

  condition:
    any of them
}
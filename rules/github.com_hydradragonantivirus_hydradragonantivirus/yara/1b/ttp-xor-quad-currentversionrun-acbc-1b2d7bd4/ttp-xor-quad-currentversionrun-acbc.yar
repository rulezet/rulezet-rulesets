rule TTP_XOR_QUAD_CurrentVersionRun_acbc {
  strings:
    $key_acbc = { ff d3 [2] db dd [2] f0 f1 [2] de d3 [2] ca c8 [2] c5 d2 [2] db cf [2] d9 ce [2] c2 c8 [2] de cf [2] c2 e0 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_afa0 {
  strings:
    $key_afa0 = { fc cf [2] d8 c1 [2] f3 ed [2] dd cf [2] c9 d4 [2] c6 ce [2] d8 d3 [2] da d2 [2] c1 d4 [2] dd d3 [2] c1 fc }

  condition:
    any of them
}
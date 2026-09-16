rule TTP_XOR_QUAD_CurrentVersionRun_aaa0 {
  strings:
    $key_aaa0 = { f9 cf [2] dd c1 [2] f6 ed [2] d8 cf [2] cc d4 [2] c3 ce [2] dd d3 [2] df d2 [2] c4 d4 [2] d8 d3 [2] c4 fc }

  condition:
    any of them
}
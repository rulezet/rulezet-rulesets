rule TTP_XOR_QUAD_CurrentVersionRun_aaa1 {
  strings:
    $key_aaa1 = { f9 ce [2] dd c0 [2] f6 ec [2] d8 ce [2] cc d5 [2] c3 cf [2] dd d2 [2] df d3 [2] c4 d5 [2] d8 d2 [2] c4 fd }

  condition:
    any of them
}
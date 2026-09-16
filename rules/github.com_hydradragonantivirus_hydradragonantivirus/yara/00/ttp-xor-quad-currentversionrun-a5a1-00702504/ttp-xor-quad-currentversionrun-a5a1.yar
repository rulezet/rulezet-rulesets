rule TTP_XOR_QUAD_CurrentVersionRun_a5a1 {
  strings:
    $key_a5a1 = { f6 ce [2] d2 c0 [2] f9 ec [2] d7 ce [2] c3 d5 [2] cc cf [2] d2 d2 [2] d0 d3 [2] cb d5 [2] d7 d2 [2] cb fd }

  condition:
    any of them
}
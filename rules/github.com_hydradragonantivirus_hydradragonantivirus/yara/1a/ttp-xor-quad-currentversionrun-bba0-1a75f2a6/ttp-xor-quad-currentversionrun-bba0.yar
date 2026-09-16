rule TTP_XOR_QUAD_CurrentVersionRun_bba0 {
  strings:
    $key_bba0 = { e8 cf [2] cc c1 [2] e7 ed [2] c9 cf [2] dd d4 [2] d2 ce [2] cc d3 [2] ce d2 [2] d5 d4 [2] c9 d3 [2] d5 fc }

  condition:
    any of them
}
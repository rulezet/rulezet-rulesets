rule TTP_XOR_QUAD_CurrentVersionRun_a4bc {
  strings:
    $key_a4bc = { f7 d3 [2] d3 dd [2] f8 f1 [2] d6 d3 [2] c2 c8 [2] cd d2 [2] d3 cf [2] d1 ce [2] ca c8 [2] d6 cf [2] ca e0 }

  condition:
    any of them
}
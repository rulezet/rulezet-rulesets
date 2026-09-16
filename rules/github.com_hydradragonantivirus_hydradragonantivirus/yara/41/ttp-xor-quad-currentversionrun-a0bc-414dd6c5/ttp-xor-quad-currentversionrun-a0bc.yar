rule TTP_XOR_QUAD_CurrentVersionRun_a0bc {
  strings:
    $key_a0bc = { f3 d3 [2] d7 dd [2] fc f1 [2] d2 d3 [2] c6 c8 [2] c9 d2 [2] d7 cf [2] d5 ce [2] ce c8 [2] d2 cf [2] ce e0 }

  condition:
    any of them
}
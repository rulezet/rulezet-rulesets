rule TTP_XOR_QUAD_CurrentVersionRun_a5bc {
  strings:
    $key_a5bc = { f6 d3 [2] d2 dd [2] f9 f1 [2] d7 d3 [2] c3 c8 [2] cc d2 [2] d2 cf [2] d0 ce [2] cb c8 [2] d7 cf [2] cb e0 }

  condition:
    any of them
}
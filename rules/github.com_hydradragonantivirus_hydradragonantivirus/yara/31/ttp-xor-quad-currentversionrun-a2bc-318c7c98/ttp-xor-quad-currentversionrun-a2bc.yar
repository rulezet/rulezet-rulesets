rule TTP_XOR_QUAD_CurrentVersionRun_a2bc {
  strings:
    $key_a2bc = { f1 d3 [2] d5 dd [2] fe f1 [2] d0 d3 [2] c4 c8 [2] cb d2 [2] d5 cf [2] d7 ce [2] cc c8 [2] d0 cf [2] cc e0 }

  condition:
    any of them
}
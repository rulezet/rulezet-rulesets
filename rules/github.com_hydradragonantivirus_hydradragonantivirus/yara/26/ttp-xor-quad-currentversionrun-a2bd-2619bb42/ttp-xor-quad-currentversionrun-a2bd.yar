rule TTP_XOR_QUAD_CurrentVersionRun_a2bd {
  strings:
    $key_a2bd = { f1 d2 [2] d5 dc [2] fe f0 [2] d0 d2 [2] c4 c9 [2] cb d3 [2] d5 ce [2] d7 cf [2] cc c9 [2] d0 ce [2] cc e1 }

  condition:
    any of them
}
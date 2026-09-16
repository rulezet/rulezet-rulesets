rule TTP_XOR_QUAD_CurrentVersionRun_e6bd {
  strings:
    $key_e6bd = { b5 d2 [2] 91 dc [2] ba f0 [2] 94 d2 [2] 80 c9 [2] 8f d3 [2] 91 ce [2] 93 cf [2] 88 c9 [2] 94 ce [2] 88 e1 }

  condition:
    any of them
}
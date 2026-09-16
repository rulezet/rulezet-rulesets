rule TTP_XOR_QUAD_CurrentVersionRun_89bd {
  strings:
    $key_89bd = { da d2 [2] fe dc [2] d5 f0 [2] fb d2 [2] ef c9 [2] e0 d3 [2] fe ce [2] fc cf [2] e7 c9 [2] fb ce [2] e7 e1 }

  condition:
    any of them
}
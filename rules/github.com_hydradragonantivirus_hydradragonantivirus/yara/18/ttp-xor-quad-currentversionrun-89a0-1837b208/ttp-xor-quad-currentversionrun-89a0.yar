rule TTP_XOR_QUAD_CurrentVersionRun_89a0 {
  strings:
    $key_89a0 = { da cf [2] fe c1 [2] d5 ed [2] fb cf [2] ef d4 [2] e0 ce [2] fe d3 [2] fc d2 [2] e7 d4 [2] fb d3 [2] e7 fc }

  condition:
    any of them
}
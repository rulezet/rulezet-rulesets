rule TTP_XOR_QUAD_CurrentVersionRun_8ebc {
  strings:
    $key_8ebc = { dd d3 [2] f9 dd [2] d2 f1 [2] fc d3 [2] e8 c8 [2] e7 d2 [2] f9 cf [2] fb ce [2] e0 c8 [2] fc cf [2] e0 e0 }

  condition:
    any of them
}
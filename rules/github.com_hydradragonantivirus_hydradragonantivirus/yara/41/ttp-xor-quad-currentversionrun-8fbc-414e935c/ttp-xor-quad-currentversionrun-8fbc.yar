rule TTP_XOR_QUAD_CurrentVersionRun_8fbc {
  strings:
    $key_8fbc = { dc d3 [2] f8 dd [2] d3 f1 [2] fd d3 [2] e9 c8 [2] e6 d2 [2] f8 cf [2] fa ce [2] e1 c8 [2] fd cf [2] e1 e0 }

  condition:
    any of them
}
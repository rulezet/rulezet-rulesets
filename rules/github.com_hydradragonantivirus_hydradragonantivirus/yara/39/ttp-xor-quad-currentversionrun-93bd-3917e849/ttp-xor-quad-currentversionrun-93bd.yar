rule TTP_XOR_QUAD_CurrentVersionRun_93bd {
  strings:
    $key_93bd = { c0 d2 [2] e4 dc [2] cf f0 [2] e1 d2 [2] f5 c9 [2] fa d3 [2] e4 ce [2] e6 cf [2] fd c9 [2] e1 ce [2] fd e1 }

  condition:
    any of them
}
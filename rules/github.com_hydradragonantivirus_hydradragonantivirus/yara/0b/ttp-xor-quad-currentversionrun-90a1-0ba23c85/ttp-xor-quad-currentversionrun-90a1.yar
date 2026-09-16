rule TTP_XOR_QUAD_CurrentVersionRun_90a1 {
  strings:
    $key_90a1 = { c3 ce [2] e7 c0 [2] cc ec [2] e2 ce [2] f6 d5 [2] f9 cf [2] e7 d2 [2] e5 d3 [2] fe d5 [2] e2 d2 [2] fe fd }

  condition:
    any of them
}
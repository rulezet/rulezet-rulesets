rule TTP_XOR_QUAD_CurrentVersionRun_8ba1 {
  strings:
    $key_8ba1 = { d8 ce [2] fc c0 [2] d7 ec [2] f9 ce [2] ed d5 [2] e2 cf [2] fc d2 [2] fe d3 [2] e5 d5 [2] f9 d2 [2] e5 fd }

  condition:
    any of them
}
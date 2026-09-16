rule TTP_XOR_QUAD_CurrentVersionRun_868f {
  strings:
    $key_868f = { d5 e0 [2] f1 ee [2] da c2 [2] f4 e0 [2] e0 fb [2] ef e1 [2] f1 fc [2] f3 fd [2] e8 fb [2] f4 fc [2] e8 d3 }

  condition:
    any of them
}
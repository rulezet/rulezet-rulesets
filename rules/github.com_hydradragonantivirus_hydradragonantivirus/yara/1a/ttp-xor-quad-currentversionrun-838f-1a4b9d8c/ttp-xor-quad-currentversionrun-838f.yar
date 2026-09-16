rule TTP_XOR_QUAD_CurrentVersionRun_838f {
  strings:
    $key_838f = { d0 e0 [2] f4 ee [2] df c2 [2] f1 e0 [2] e5 fb [2] ea e1 [2] f4 fc [2] f6 fd [2] ed fb [2] f1 fc [2] ed d3 }

  condition:
    any of them
}
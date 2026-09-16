rule TTP_XOR_QUAD_CurrentVersionRun_818f {
  strings:
    $key_818f = { d2 e0 [2] f6 ee [2] dd c2 [2] f3 e0 [2] e7 fb [2] e8 e1 [2] f6 fc [2] f4 fd [2] ef fb [2] f3 fc [2] ef d3 }

  condition:
    any of them
}
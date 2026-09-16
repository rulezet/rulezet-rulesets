rule TTP_XOR_QUAD_CurrentVersionRun_8593 {
  strings:
    $key_8593 = { d6 fc [2] f2 f2 [2] d9 de [2] f7 fc [2] e3 e7 [2] ec fd [2] f2 e0 [2] f0 e1 [2] eb e7 [2] f7 e0 [2] eb cf }

  condition:
    any of them
}
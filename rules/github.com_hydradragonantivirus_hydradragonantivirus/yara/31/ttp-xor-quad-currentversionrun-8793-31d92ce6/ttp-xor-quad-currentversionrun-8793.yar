rule TTP_XOR_QUAD_CurrentVersionRun_8793 {
  strings:
    $key_8793 = { d4 fc [2] f0 f2 [2] db de [2] f5 fc [2] e1 e7 [2] ee fd [2] f0 e0 [2] f2 e1 [2] e9 e7 [2] f5 e0 [2] e9 cf }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_8391 {
  strings:
    $key_8391 = { d0 fe [2] f4 f0 [2] df dc [2] f1 fe [2] e5 e5 [2] ea ff [2] f4 e2 [2] f6 e3 [2] ed e5 [2] f1 e2 [2] ed cd }

  condition:
    any of them
}
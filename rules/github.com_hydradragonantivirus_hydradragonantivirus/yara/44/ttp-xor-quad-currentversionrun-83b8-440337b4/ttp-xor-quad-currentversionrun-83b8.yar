rule TTP_XOR_QUAD_CurrentVersionRun_83b8 {
  strings:
    $key_83b8 = { d0 d7 [2] f4 d9 [2] df f5 [2] f1 d7 [2] e5 cc [2] ea d6 [2] f4 cb [2] f6 ca [2] ed cc [2] f1 cb [2] ed e4 }

  condition:
    any of them
}
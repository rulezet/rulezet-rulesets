rule TTP_XOR_QUAD_CurrentVersionRun_989b {
  strings:
    $key_989b = { cb f4 [2] ef fa [2] c4 d6 [2] ea f4 [2] fe ef [2] f1 f5 [2] ef e8 [2] ed e9 [2] f6 ef [2] ea e8 [2] f6 c7 }

  condition:
    any of them
}
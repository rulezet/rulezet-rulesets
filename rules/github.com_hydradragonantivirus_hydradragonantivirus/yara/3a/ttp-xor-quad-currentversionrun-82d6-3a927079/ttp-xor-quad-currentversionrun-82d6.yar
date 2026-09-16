rule TTP_XOR_QUAD_CurrentVersionRun_82d6 {
  strings:
    $key_82d6 = { d1 b9 [2] f5 b7 [2] de 9b [2] f0 b9 [2] e4 a2 [2] eb b8 [2] f5 a5 [2] f7 a4 [2] ec a2 [2] f0 a5 [2] ec 8a }

  condition:
    any of them
}
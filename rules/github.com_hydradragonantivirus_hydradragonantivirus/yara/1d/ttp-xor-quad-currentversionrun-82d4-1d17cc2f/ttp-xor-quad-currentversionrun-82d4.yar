rule TTP_XOR_QUAD_CurrentVersionRun_82d4 {
  strings:
    $key_82d4 = { d1 bb [2] f5 b5 [2] de 99 [2] f0 bb [2] e4 a0 [2] eb ba [2] f5 a7 [2] f7 a6 [2] ec a0 [2] f0 a7 [2] ec 88 }

  condition:
    any of them
}
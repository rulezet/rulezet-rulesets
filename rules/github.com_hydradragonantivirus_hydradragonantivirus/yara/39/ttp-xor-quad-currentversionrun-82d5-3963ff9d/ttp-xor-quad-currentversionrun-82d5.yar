rule TTP_XOR_QUAD_CurrentVersionRun_82d5 {
  strings:
    $key_82d5 = { d1 ba [2] f5 b4 [2] de 98 [2] f0 ba [2] e4 a1 [2] eb bb [2] f5 a6 [2] f7 a7 [2] ec a1 [2] f0 a6 [2] ec 89 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_8682 {
  strings:
    $key_8682 = { d5 ed [2] f1 e3 [2] da cf [2] f4 ed [2] e0 f6 [2] ef ec [2] f1 f1 [2] f3 f0 [2] e8 f6 [2] f4 f1 [2] e8 de }

  condition:
    any of them
}
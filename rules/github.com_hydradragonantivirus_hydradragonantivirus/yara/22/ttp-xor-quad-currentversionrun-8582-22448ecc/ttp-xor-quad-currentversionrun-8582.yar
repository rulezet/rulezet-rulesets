rule TTP_XOR_QUAD_CurrentVersionRun_8582 {
  strings:
    $key_8582 = { d6 ed [2] f2 e3 [2] d9 cf [2] f7 ed [2] e3 f6 [2] ec ec [2] f2 f1 [2] f0 f0 [2] eb f6 [2] f7 f1 [2] eb de }

  condition:
    any of them
}
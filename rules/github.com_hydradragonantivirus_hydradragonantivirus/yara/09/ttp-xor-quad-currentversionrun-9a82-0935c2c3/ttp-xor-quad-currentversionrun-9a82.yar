rule TTP_XOR_QUAD_CurrentVersionRun_9a82 {
  strings:
    $key_9a82 = { c9 ed [2] ed e3 [2] c6 cf [2] e8 ed [2] fc f6 [2] f3 ec [2] ed f1 [2] ef f0 [2] f4 f6 [2] e8 f1 [2] f4 de }

  condition:
    any of them
}
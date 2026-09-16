rule TTP_XOR_QUAD_CurrentVersionRun_8082 {
  strings:
    $key_8082 = { d3 ed [2] f7 e3 [2] dc cf [2] f2 ed [2] e6 f6 [2] e9 ec [2] f7 f1 [2] f5 f0 [2] ee f6 [2] f2 f1 [2] ee de }

  condition:
    any of them
}
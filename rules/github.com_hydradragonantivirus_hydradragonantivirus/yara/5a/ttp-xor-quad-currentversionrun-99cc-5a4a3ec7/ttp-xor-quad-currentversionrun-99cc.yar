rule TTP_XOR_QUAD_CurrentVersionRun_99cc {
  strings:
    $key_99cc = { ca a3 [2] ee ad [2] c5 81 [2] eb a3 [2] ff b8 [2] f0 a2 [2] ee bf [2] ec be [2] f7 b8 [2] eb bf [2] f7 90 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_8099 {
  strings:
    $key_8099 = { d3 f6 [2] f7 f8 [2] dc d4 [2] f2 f6 [2] e6 ed [2] e9 f7 [2] f7 ea [2] f5 eb [2] ee ed [2] f2 ea [2] ee c5 }

  condition:
    any of them
}
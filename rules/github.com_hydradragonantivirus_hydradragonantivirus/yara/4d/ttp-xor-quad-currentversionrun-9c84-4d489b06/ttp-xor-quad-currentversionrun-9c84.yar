rule TTP_XOR_QUAD_CurrentVersionRun_9c84 {
  strings:
    $key_9c84 = { cf eb [2] eb e5 [2] c0 c9 [2] ee eb [2] fa f0 [2] f5 ea [2] eb f7 [2] e9 f6 [2] f2 f0 [2] ee f7 [2] f2 d8 }

  condition:
    any of them
}
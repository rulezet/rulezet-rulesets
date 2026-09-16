rule TTP_XOR_QUAD_CurrentVersionRun_9d84 {
  strings:
    $key_9d84 = { ce eb [2] ea e5 [2] c1 c9 [2] ef eb [2] fb f0 [2] f4 ea [2] ea f7 [2] e8 f6 [2] f3 f0 [2] ef f7 [2] f3 d8 }

  condition:
    any of them
}
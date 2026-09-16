rule TTP_XOR_QUAD_CurrentVersionRun_9d46 {
  strings:
    $key_9d46 = { ce 29 [2] ea 27 [2] c1 0b [2] ef 29 [2] fb 32 [2] f4 28 [2] ea 35 [2] e8 34 [2] f3 32 [2] ef 35 [2] f3 1a }

  condition:
    any of them
}
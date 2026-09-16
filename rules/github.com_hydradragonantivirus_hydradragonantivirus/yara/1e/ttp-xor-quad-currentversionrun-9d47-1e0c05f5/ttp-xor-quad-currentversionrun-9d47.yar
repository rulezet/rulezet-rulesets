rule TTP_XOR_QUAD_CurrentVersionRun_9d47 {
  strings:
    $key_9d47 = { ce 28 [2] ea 26 [2] c1 0a [2] ef 28 [2] fb 33 [2] f4 29 [2] ea 34 [2] e8 35 [2] f3 33 [2] ef 34 [2] f3 1b }

  condition:
    any of them
}
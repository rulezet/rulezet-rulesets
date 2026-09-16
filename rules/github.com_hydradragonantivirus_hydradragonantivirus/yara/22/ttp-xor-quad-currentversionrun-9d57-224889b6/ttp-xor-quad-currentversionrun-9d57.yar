rule TTP_XOR_QUAD_CurrentVersionRun_9d57 {
  strings:
    $key_9d57 = { ce 38 [2] ea 36 [2] c1 1a [2] ef 38 [2] fb 23 [2] f4 39 [2] ea 24 [2] e8 25 [2] f3 23 [2] ef 24 [2] f3 0b }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9d56 {
  strings:
    $key_9d56 = { ce 39 [2] ea 37 [2] c1 1b [2] ef 39 [2] fb 22 [2] f4 38 [2] ea 25 [2] e8 24 [2] f3 22 [2] ef 25 [2] f3 0a }

  condition:
    any of them
}
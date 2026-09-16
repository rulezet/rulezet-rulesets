rule TTP_XOR_QUAD_CurrentVersionRun_9d44 {
  strings:
    $key_9d44 = { ce 2b [2] ea 25 [2] c1 09 [2] ef 2b [2] fb 30 [2] f4 2a [2] ea 37 [2] e8 36 [2] f3 30 [2] ef 37 [2] f3 18 }

  condition:
    any of them
}
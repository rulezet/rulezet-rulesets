rule TTP_XOR_QUAD_CurrentVersionRun_9d59 {
  strings:
    $key_9d59 = { ce 36 [2] ea 38 [2] c1 14 [2] ef 36 [2] fb 2d [2] f4 37 [2] ea 2a [2] e8 2b [2] f3 2d [2] ef 2a [2] f3 05 }

  condition:
    any of them
}
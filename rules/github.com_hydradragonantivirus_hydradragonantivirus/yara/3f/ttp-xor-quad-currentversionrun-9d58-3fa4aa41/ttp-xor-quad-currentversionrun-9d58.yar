rule TTP_XOR_QUAD_CurrentVersionRun_9d58 {
  strings:
    $key_9d58 = { ce 37 [2] ea 39 [2] c1 15 [2] ef 37 [2] fb 2c [2] f4 36 [2] ea 2b [2] e8 2a [2] f3 2c [2] ef 2b [2] f3 04 }

  condition:
    any of them
}
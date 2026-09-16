rule TTP_XOR_QUAD_CurrentVersionRun_9d43 {
  strings:
    $key_9d43 = { ce 2c [2] ea 22 [2] c1 0e [2] ef 2c [2] fb 37 [2] f4 2d [2] ea 30 [2] e8 31 [2] f3 37 [2] ef 30 [2] f3 1f }

  condition:
    any of them
}
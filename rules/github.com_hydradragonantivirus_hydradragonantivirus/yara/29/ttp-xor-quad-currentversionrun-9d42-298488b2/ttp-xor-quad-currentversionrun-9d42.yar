rule TTP_XOR_QUAD_CurrentVersionRun_9d42 {
  strings:
    $key_9d42 = { ce 2d [2] ea 23 [2] c1 0f [2] ef 2d [2] fb 36 [2] f4 2c [2] ea 31 [2] e8 30 [2] f3 36 [2] ef 31 [2] f3 1e }

  condition:
    any of them
}
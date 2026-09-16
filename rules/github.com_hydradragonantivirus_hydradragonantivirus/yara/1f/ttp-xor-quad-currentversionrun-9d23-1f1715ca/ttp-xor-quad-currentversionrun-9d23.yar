rule TTP_XOR_QUAD_CurrentVersionRun_9d23 {
  strings:
    $key_9d23 = { ce 4c [2] ea 42 [2] c1 6e [2] ef 4c [2] fb 57 [2] f4 4d [2] ea 50 [2] e8 51 [2] f3 57 [2] ef 50 [2] f3 7f }

  condition:
    any of them
}
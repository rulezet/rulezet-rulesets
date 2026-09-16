rule TTP_XOR_QUAD_CurrentVersionRun_9d03 {
  strings:
    $key_9d03 = { ce 6c [2] ea 62 [2] c1 4e [2] ef 6c [2] fb 77 [2] f4 6d [2] ea 70 [2] e8 71 [2] f3 77 [2] ef 70 [2] f3 5f }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9d6f {
  strings:
    $key_9d6f = { ce 00 [2] ea 0e [2] c1 22 [2] ef 00 [2] fb 1b [2] f4 01 [2] ea 1c [2] e8 1d [2] f3 1b [2] ef 1c [2] f3 33 }

  condition:
    any of them
}
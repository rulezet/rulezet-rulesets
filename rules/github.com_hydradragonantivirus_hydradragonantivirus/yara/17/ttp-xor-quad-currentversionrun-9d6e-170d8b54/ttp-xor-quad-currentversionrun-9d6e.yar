rule TTP_XOR_QUAD_CurrentVersionRun_9d6e {
  strings:
    $key_9d6e = { ce 01 [2] ea 0f [2] c1 23 [2] ef 01 [2] fb 1a [2] f4 00 [2] ea 1d [2] e8 1c [2] f3 1a [2] ef 1d [2] f3 32 }

  condition:
    any of them
}
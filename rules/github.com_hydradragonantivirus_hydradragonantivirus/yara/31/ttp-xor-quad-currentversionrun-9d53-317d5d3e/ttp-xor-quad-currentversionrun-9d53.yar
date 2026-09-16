rule TTP_XOR_QUAD_CurrentVersionRun_9d53 {
  strings:
    $key_9d53 = { ce 3c [2] ea 32 [2] c1 1e [2] ef 3c [2] fb 27 [2] f4 3d [2] ea 20 [2] e8 21 [2] f3 27 [2] ef 20 [2] f3 0f }

  condition:
    any of them
}
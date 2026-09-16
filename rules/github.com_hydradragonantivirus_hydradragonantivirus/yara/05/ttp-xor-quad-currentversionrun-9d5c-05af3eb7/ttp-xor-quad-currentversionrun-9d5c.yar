rule TTP_XOR_QUAD_CurrentVersionRun_9d5c {
  strings:
    $key_9d5c = { ce 33 [2] ea 3d [2] c1 11 [2] ef 33 [2] fb 28 [2] f4 32 [2] ea 2f [2] e8 2e [2] f3 28 [2] ef 2f [2] f3 00 }

  condition:
    any of them
}
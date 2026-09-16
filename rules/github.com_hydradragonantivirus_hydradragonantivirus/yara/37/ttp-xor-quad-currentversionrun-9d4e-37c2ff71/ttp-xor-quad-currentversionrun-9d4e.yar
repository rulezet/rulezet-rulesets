rule TTP_XOR_QUAD_CurrentVersionRun_9d4e {
  strings:
    $key_9d4e = { ce 21 [2] ea 2f [2] c1 03 [2] ef 21 [2] fb 3a [2] f4 20 [2] ea 3d [2] e8 3c [2] f3 3a [2] ef 3d [2] f3 12 }

  condition:
    any of them
}
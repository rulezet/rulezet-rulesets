rule TTP_XOR_QUAD_CurrentVersionRun_9dee {
  strings:
    $key_9dee = { ce 81 [2] ea 8f [2] c1 a3 [2] ef 81 [2] fb 9a [2] f4 80 [2] ea 9d [2] e8 9c [2] f3 9a [2] ef 9d [2] f3 b2 }

  condition:
    any of them
}
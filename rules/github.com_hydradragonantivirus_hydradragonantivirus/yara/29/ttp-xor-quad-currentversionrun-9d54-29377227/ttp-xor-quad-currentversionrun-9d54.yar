rule TTP_XOR_QUAD_CurrentVersionRun_9d54 {
  strings:
    $key_9d54 = { ce 3b [2] ea 35 [2] c1 19 [2] ef 3b [2] fb 20 [2] f4 3a [2] ea 27 [2] e8 26 [2] f3 20 [2] ef 27 [2] f3 08 }

  condition:
    any of them
}
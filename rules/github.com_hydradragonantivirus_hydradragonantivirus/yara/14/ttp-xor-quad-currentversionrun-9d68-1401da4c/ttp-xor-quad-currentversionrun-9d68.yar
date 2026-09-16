rule TTP_XOR_QUAD_CurrentVersionRun_9d68 {
  strings:
    $key_9d68 = { ce 07 [2] ea 09 [2] c1 25 [2] ef 07 [2] fb 1c [2] f4 06 [2] ea 1b [2] e8 1a [2] f3 1c [2] ef 1b [2] f3 34 }

  condition:
    any of them
}
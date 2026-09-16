rule TTP_XOR_QUAD_CurrentVersionRun_9d75 {
  strings:
    $key_9d75 = { ce 1a [2] ea 14 [2] c1 38 [2] ef 1a [2] fb 01 [2] f4 1b [2] ea 06 [2] e8 07 [2] f3 01 [2] ef 06 [2] f3 29 }

  condition:
    any of them
}
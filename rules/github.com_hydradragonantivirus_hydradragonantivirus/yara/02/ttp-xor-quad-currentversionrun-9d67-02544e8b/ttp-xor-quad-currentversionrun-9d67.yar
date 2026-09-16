rule TTP_XOR_QUAD_CurrentVersionRun_9d67 {
  strings:
    $key_9d67 = { ce 08 [2] ea 06 [2] c1 2a [2] ef 08 [2] fb 13 [2] f4 09 [2] ea 14 [2] e8 15 [2] f3 13 [2] ef 14 [2] f3 3b }

  condition:
    any of them
}
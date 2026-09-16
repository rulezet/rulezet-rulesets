rule TTP_XOR_QUAD_CurrentVersionRun_9d34 {
  strings:
    $key_9d34 = { ce 5b [2] ea 55 [2] c1 79 [2] ef 5b [2] fb 40 [2] f4 5a [2] ea 47 [2] e8 46 [2] f3 40 [2] ef 47 [2] f3 68 }

  condition:
    any of them
}
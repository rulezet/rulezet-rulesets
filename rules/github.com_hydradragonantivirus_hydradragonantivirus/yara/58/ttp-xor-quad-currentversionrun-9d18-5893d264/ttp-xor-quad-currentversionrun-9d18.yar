rule TTP_XOR_QUAD_CurrentVersionRun_9d18 {
  strings:
    $key_9d18 = { ce 77 [2] ea 79 [2] c1 55 [2] ef 77 [2] fb 6c [2] f4 76 [2] ea 6b [2] e8 6a [2] f3 6c [2] ef 6b [2] f3 44 }

  condition:
    any of them
}
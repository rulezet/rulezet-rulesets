rule TTP_XOR_QUAD_CurrentVersionRun_9d08 {
  strings:
    $key_9d08 = { ce 67 [2] ea 69 [2] c1 45 [2] ef 67 [2] fb 7c [2] f4 66 [2] ea 7b [2] e8 7a [2] f3 7c [2] ef 7b [2] f3 54 }

  condition:
    any of them
}
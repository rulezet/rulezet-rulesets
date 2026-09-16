rule TTP_XOR_QUAD_CurrentVersionRun_9de8 {
  strings:
    $key_9de8 = { ce 87 [2] ea 89 [2] c1 a5 [2] ef 87 [2] fb 9c [2] f4 86 [2] ea 9b [2] e8 9a [2] f3 9c [2] ef 9b [2] f3 b4 }

  condition:
    any of them
}
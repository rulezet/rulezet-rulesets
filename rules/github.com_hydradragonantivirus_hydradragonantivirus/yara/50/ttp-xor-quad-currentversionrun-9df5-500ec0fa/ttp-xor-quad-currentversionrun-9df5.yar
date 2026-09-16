rule TTP_XOR_QUAD_CurrentVersionRun_9df5 {
  strings:
    $key_9df5 = { ce 9a [2] ea 94 [2] c1 b8 [2] ef 9a [2] fb 81 [2] f4 9b [2] ea 86 [2] e8 87 [2] f3 81 [2] ef 86 [2] f3 a9 }

  condition:
    any of them
}
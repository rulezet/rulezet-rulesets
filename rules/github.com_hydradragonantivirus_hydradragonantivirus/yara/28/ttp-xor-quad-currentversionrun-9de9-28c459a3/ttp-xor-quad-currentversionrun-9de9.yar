rule TTP_XOR_QUAD_CurrentVersionRun_9de9 {
  strings:
    $key_9de9 = { ce 86 [2] ea 88 [2] c1 a4 [2] ef 86 [2] fb 9d [2] f4 87 [2] ea 9a [2] e8 9b [2] f3 9d [2] ef 9a [2] f3 b5 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9df8 {
  strings:
    $key_9df8 = { ce 97 [2] ea 99 [2] c1 b5 [2] ef 97 [2] fb 8c [2] f4 96 [2] ea 8b [2] e8 8a [2] f3 8c [2] ef 8b [2] f3 a4 }

  condition:
    any of them
}
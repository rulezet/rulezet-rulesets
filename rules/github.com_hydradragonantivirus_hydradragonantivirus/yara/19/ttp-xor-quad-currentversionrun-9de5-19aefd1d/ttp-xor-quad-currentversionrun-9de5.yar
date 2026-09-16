rule TTP_XOR_QUAD_CurrentVersionRun_9de5 {
  strings:
    $key_9de5 = { ce 8a [2] ea 84 [2] c1 a8 [2] ef 8a [2] fb 91 [2] f4 8b [2] ea 96 [2] e8 97 [2] f3 91 [2] ef 96 [2] f3 b9 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9df9 {
  strings:
    $key_9df9 = { ce 96 [2] ea 98 [2] c1 b4 [2] ef 96 [2] fb 8d [2] f4 97 [2] ea 8a [2] e8 8b [2] f3 8d [2] ef 8a [2] f3 a5 }

  condition:
    any of them
}
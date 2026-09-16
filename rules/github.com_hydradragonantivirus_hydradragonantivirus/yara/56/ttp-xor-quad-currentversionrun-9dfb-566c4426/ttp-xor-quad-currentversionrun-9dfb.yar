rule TTP_XOR_QUAD_CurrentVersionRun_9dfb {
  strings:
    $key_9dfb = { ce 94 [2] ea 9a [2] c1 b6 [2] ef 94 [2] fb 8f [2] f4 95 [2] ea 88 [2] e8 89 [2] f3 8f [2] ef 88 [2] f3 a7 }

  condition:
    any of them
}
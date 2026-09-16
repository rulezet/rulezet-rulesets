rule TTP_XOR_QUAD_CurrentVersionRun_9d7a {
  strings:
    $key_9d7a = { ce 15 [2] ea 1b [2] c1 37 [2] ef 15 [2] fb 0e [2] f4 14 [2] ea 09 [2] e8 08 [2] f3 0e [2] ef 09 [2] f3 26 }

  condition:
    any of them
}
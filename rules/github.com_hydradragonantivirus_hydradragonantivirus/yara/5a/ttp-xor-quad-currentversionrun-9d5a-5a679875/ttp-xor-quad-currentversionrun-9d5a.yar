rule TTP_XOR_QUAD_CurrentVersionRun_9d5a {
  strings:
    $key_9d5a = { ce 35 [2] ea 3b [2] c1 17 [2] ef 35 [2] fb 2e [2] f4 34 [2] ea 29 [2] e8 28 [2] f3 2e [2] ef 29 [2] f3 06 }

  condition:
    any of them
}
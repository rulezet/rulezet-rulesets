rule TTP_XOR_QUAD_CurrentVersionRun_9d1a {
  strings:
    $key_9d1a = { ce 75 [2] ea 7b [2] c1 57 [2] ef 75 [2] fb 6e [2] f4 74 [2] ea 69 [2] e8 68 [2] f3 6e [2] ef 69 [2] f3 46 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9d1d {
  strings:
    $key_9d1d = { ce 72 [2] ea 7c [2] c1 50 [2] ef 72 [2] fb 69 [2] f4 73 [2] ea 6e [2] e8 6f [2] f3 69 [2] ef 6e [2] f3 41 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9dfd {
  strings:
    $key_9dfd = { ce 92 [2] ea 9c [2] c1 b0 [2] ef 92 [2] fb 89 [2] f4 93 [2] ea 8e [2] e8 8f [2] f3 89 [2] ef 8e [2] f3 a1 }

  condition:
    any of them
}
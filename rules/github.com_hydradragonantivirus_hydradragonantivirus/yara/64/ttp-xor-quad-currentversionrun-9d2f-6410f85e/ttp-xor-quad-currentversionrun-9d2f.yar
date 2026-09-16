rule TTP_XOR_QUAD_CurrentVersionRun_9d2f {
  strings:
    $key_9d2f = { ce 40 [2] ea 4e [2] c1 62 [2] ef 40 [2] fb 5b [2] f4 41 [2] ea 5c [2] e8 5d [2] f3 5b [2] ef 5c [2] f3 73 }

  condition:
    any of them
}
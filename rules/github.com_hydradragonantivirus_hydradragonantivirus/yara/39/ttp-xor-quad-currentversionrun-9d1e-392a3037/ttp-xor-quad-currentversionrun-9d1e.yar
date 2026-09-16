rule TTP_XOR_QUAD_CurrentVersionRun_9d1e {
  strings:
    $key_9d1e = { ce 71 [2] ea 7f [2] c1 53 [2] ef 71 [2] fb 6a [2] f4 70 [2] ea 6d [2] e8 6c [2] f3 6a [2] ef 6d [2] f3 42 }

  condition:
    any of them
}
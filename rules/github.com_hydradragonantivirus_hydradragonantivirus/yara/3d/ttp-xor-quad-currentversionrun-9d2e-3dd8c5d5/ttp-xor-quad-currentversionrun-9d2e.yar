rule TTP_XOR_QUAD_CurrentVersionRun_9d2e {
  strings:
    $key_9d2e = { ce 41 [2] ea 4f [2] c1 63 [2] ef 41 [2] fb 5a [2] f4 40 [2] ea 5d [2] e8 5c [2] f3 5a [2] ef 5d [2] f3 72 }

  condition:
    any of them
}
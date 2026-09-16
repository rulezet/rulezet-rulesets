rule TTP_XOR_QUAD_CurrentVersionRun_9d38 {
  strings:
    $key_9d38 = { ce 57 [2] ea 59 [2] c1 75 [2] ef 57 [2] fb 4c [2] f4 56 [2] ea 4b [2] e8 4a [2] f3 4c [2] ef 4b [2] f3 64 }

  condition:
    any of them
}
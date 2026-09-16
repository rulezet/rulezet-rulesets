rule TTP_XOR_QUAD_CurrentVersionRun_9d05 {
  strings:
    $key_9d05 = { ce 6a [2] ea 64 [2] c1 48 [2] ef 6a [2] fb 71 [2] f4 6b [2] ea 76 [2] e8 77 [2] f3 71 [2] ef 76 [2] f3 59 }

  condition:
    any of them
}
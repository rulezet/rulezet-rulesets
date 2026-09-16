rule TTP_XOR_QUAD_CurrentVersionRun_9874 {
  strings:
    $key_9874 = { cb 1b [2] ef 15 [2] c4 39 [2] ea 1b [2] fe 00 [2] f1 1a [2] ef 07 [2] ed 06 [2] f6 00 [2] ea 07 [2] f6 28 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9854 {
  strings:
    $key_9854 = { cb 3b [2] ef 35 [2] c4 19 [2] ea 3b [2] fe 20 [2] f1 3a [2] ef 27 [2] ed 26 [2] f6 20 [2] ea 27 [2] f6 08 }

  condition:
    any of them
}
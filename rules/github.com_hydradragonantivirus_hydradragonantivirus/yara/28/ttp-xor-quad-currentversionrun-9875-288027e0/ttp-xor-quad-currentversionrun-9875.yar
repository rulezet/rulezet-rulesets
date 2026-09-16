rule TTP_XOR_QUAD_CurrentVersionRun_9875 {
  strings:
    $key_9875 = { cb 1a [2] ef 14 [2] c4 38 [2] ea 1a [2] fe 01 [2] f1 1b [2] ef 06 [2] ed 07 [2] f6 01 [2] ea 06 [2] f6 29 }

  condition:
    any of them
}
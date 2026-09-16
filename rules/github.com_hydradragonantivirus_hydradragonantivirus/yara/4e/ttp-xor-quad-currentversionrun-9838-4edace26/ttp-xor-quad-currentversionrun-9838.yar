rule TTP_XOR_QUAD_CurrentVersionRun_9838 {
  strings:
    $key_9838 = { cb 57 [2] ef 59 [2] c4 75 [2] ea 57 [2] fe 4c [2] f1 56 [2] ef 4b [2] ed 4a [2] f6 4c [2] ea 4b [2] f6 64 }

  condition:
    any of them
}
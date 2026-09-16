rule TTP_XOR_QUAD_CurrentVersionRun_9864 {
  strings:
    $key_9864 = { cb 0b [2] ef 05 [2] c4 29 [2] ea 0b [2] fe 10 [2] f1 0a [2] ef 17 [2] ed 16 [2] f6 10 [2] ea 17 [2] f6 38 }

  condition:
    any of them
}
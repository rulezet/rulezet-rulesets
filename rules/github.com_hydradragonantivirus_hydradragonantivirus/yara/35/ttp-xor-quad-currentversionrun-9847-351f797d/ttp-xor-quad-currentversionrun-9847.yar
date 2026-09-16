rule TTP_XOR_QUAD_CurrentVersionRun_9847 {
  strings:
    $key_9847 = { cb 28 [2] ef 26 [2] c4 0a [2] ea 28 [2] fe 33 [2] f1 29 [2] ef 34 [2] ed 35 [2] f6 33 [2] ea 34 [2] f6 1b }

  condition:
    any of them
}
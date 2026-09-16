rule TTP_XOR_QUAD_CurrentVersionRun_9867 {
  strings:
    $key_9867 = { cb 08 [2] ef 06 [2] c4 2a [2] ea 08 [2] fe 13 [2] f1 09 [2] ef 14 [2] ed 15 [2] f6 13 [2] ea 14 [2] f6 3b }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9827 {
  strings:
    $key_9827 = { cb 48 [2] ef 46 [2] c4 6a [2] ea 48 [2] fe 53 [2] f1 49 [2] ef 54 [2] ed 55 [2] f6 53 [2] ea 54 [2] f6 7b }

  condition:
    any of them
}
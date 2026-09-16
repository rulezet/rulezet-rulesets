rule TTP_XOR_QUAD_CurrentVersionRun_9807 {
  strings:
    $key_9807 = { cb 68 [2] ef 66 [2] c4 4a [2] ea 68 [2] fe 73 [2] f1 69 [2] ef 74 [2] ed 75 [2] f6 73 [2] ea 74 [2] f6 5b }

  condition:
    any of them
}
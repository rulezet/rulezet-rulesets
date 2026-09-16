rule TTP_XOR_QUAD_CurrentVersionRun_9825 {
  strings:
    $key_9825 = { cb 4a [2] ef 44 [2] c4 68 [2] ea 4a [2] fe 51 [2] f1 4b [2] ef 56 [2] ed 57 [2] f6 51 [2] ea 56 [2] f6 79 }

  condition:
    any of them
}
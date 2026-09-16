rule TTP_XOR_QUAD_CurrentVersionRun_9804 {
  strings:
    $key_9804 = { cb 6b [2] ef 65 [2] c4 49 [2] ea 6b [2] fe 70 [2] f1 6a [2] ef 77 [2] ed 76 [2] f6 70 [2] ea 77 [2] f6 58 }

  condition:
    any of them
}
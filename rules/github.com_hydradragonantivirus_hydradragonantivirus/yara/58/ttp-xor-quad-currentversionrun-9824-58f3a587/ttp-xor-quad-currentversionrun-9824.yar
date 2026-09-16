rule TTP_XOR_QUAD_CurrentVersionRun_9824 {
  strings:
    $key_9824 = { cb 4b [2] ef 45 [2] c4 69 [2] ea 4b [2] fe 50 [2] f1 4a [2] ef 57 [2] ed 56 [2] f6 50 [2] ea 57 [2] f6 78 }

  condition:
    any of them
}
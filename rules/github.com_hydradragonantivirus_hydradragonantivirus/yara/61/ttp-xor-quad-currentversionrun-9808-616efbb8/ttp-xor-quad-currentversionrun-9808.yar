rule TTP_XOR_QUAD_CurrentVersionRun_9808 {
  strings:
    $key_9808 = { cb 67 [2] ef 69 [2] c4 45 [2] ea 67 [2] fe 7c [2] f1 66 [2] ef 7b [2] ed 7a [2] f6 7c [2] ea 7b [2] f6 54 }

  condition:
    any of them
}
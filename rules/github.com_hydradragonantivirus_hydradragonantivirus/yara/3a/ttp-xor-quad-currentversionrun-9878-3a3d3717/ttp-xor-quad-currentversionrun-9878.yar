rule TTP_XOR_QUAD_CurrentVersionRun_9878 {
  strings:
    $key_9878 = { cb 17 [2] ef 19 [2] c4 35 [2] ea 17 [2] fe 0c [2] f1 16 [2] ef 0b [2] ed 0a [2] f6 0c [2] ea 0b [2] f6 24 }

  condition:
    any of them
}
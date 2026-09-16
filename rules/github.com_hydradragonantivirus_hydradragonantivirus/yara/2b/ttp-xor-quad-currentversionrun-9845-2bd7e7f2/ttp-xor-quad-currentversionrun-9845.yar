rule TTP_XOR_QUAD_CurrentVersionRun_9845 {
  strings:
    $key_9845 = { cb 2a [2] ef 24 [2] c4 08 [2] ea 2a [2] fe 31 [2] f1 2b [2] ef 36 [2] ed 37 [2] f6 31 [2] ea 36 [2] f6 19 }

  condition:
    any of them
}
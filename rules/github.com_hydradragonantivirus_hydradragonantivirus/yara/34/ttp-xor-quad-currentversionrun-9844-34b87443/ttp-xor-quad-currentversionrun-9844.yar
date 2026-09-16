rule TTP_XOR_QUAD_CurrentVersionRun_9844 {
  strings:
    $key_9844 = { cb 2b [2] ef 25 [2] c4 09 [2] ea 2b [2] fe 30 [2] f1 2a [2] ef 37 [2] ed 36 [2] f6 30 [2] ea 37 [2] f6 18 }

  condition:
    any of them
}
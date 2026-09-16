rule TTP_XOR_QUAD_CurrentVersionRun_9858 {
  strings:
    $key_9858 = { cb 37 [2] ef 39 [2] c4 15 [2] ea 37 [2] fe 2c [2] f1 36 [2] ef 2b [2] ed 2a [2] f6 2c [2] ea 2b [2] f6 04 }

  condition:
    any of them
}
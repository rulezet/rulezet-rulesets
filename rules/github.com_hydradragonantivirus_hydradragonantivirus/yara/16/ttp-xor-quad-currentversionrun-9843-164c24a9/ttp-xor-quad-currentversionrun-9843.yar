rule TTP_XOR_QUAD_CurrentVersionRun_9843 {
  strings:
    $key_9843 = { cb 2c [2] ef 22 [2] c4 0e [2] ea 2c [2] fe 37 [2] f1 2d [2] ef 30 [2] ed 31 [2] f6 37 [2] ea 30 [2] f6 1f }

  condition:
    any of them
}
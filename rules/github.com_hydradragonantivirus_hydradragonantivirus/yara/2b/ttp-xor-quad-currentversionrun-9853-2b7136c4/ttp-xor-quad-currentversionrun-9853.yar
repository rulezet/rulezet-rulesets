rule TTP_XOR_QUAD_CurrentVersionRun_9853 {
  strings:
    $key_9853 = { cb 3c [2] ef 32 [2] c4 1e [2] ea 3c [2] fe 27 [2] f1 3d [2] ef 20 [2] ed 21 [2] f6 27 [2] ea 20 [2] f6 0f }

  condition:
    any of them
}
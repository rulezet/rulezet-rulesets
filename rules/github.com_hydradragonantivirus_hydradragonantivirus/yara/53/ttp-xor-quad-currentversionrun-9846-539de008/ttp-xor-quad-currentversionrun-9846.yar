rule TTP_XOR_QUAD_CurrentVersionRun_9846 {
  strings:
    $key_9846 = { cb 29 [2] ef 27 [2] c4 0b [2] ea 29 [2] fe 32 [2] f1 28 [2] ef 35 [2] ed 34 [2] f6 32 [2] ea 35 [2] f6 1a }

  condition:
    any of them
}
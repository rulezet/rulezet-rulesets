rule TTP_XOR_QUAD_CurrentVersionRun_9860 {
  strings:
    $key_9860 = { cb 0f [2] ef 01 [2] c4 2d [2] ea 0f [2] fe 14 [2] f1 0e [2] ef 13 [2] ed 12 [2] f6 14 [2] ea 13 [2] f6 3c }

  condition:
    any of them
}
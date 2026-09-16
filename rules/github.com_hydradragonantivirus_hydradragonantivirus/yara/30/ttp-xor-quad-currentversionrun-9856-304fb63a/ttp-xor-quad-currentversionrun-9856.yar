rule TTP_XOR_QUAD_CurrentVersionRun_9856 {
  strings:
    $key_9856 = { cb 39 [2] ef 37 [2] c4 1b [2] ea 39 [2] fe 22 [2] f1 38 [2] ef 25 [2] ed 24 [2] f6 22 [2] ea 25 [2] f6 0a }

  condition:
    any of them
}
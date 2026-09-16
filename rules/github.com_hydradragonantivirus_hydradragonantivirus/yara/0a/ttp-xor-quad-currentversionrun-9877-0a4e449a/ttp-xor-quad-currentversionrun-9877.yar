rule TTP_XOR_QUAD_CurrentVersionRun_9877 {
  strings:
    $key_9877 = { cb 18 [2] ef 16 [2] c4 3a [2] ea 18 [2] fe 03 [2] f1 19 [2] ef 04 [2] ed 05 [2] f6 03 [2] ea 04 [2] f6 2b }

  condition:
    any of them
}
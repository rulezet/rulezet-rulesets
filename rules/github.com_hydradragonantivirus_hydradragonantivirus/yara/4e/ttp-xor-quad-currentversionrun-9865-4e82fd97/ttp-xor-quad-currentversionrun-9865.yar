rule TTP_XOR_QUAD_CurrentVersionRun_9865 {
  strings:
    $key_9865 = { cb 0a [2] ef 04 [2] c4 28 [2] ea 0a [2] fe 11 [2] f1 0b [2] ef 16 [2] ed 17 [2] f6 11 [2] ea 16 [2] f6 39 }

  condition:
    any of them
}
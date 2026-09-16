rule TTP_XOR_QUAD_CurrentVersionRun_985c {
  strings:
    $key_985c = { cb 33 [2] ef 3d [2] c4 11 [2] ea 33 [2] fe 28 [2] f1 32 [2] ef 2f [2] ed 2e [2] f6 28 [2] ea 2f [2] f6 00 }

  condition:
    any of them
}
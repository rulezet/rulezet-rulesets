rule TTP_XOR_QUAD_CurrentVersionRun_984d {
  strings:
    $key_984d = { cb 22 [2] ef 2c [2] c4 00 [2] ea 22 [2] fe 39 [2] f1 23 [2] ef 3e [2] ed 3f [2] f6 39 [2] ea 3e [2] f6 11 }

  condition:
    any of them
}
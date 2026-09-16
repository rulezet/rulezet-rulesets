rule TTP_XOR_QUAD_CurrentVersionRun_984e {
  strings:
    $key_984e = { cb 21 [2] ef 2f [2] c4 03 [2] ea 21 [2] fe 3a [2] f1 20 [2] ef 3d [2] ed 3c [2] f6 3a [2] ea 3d [2] f6 12 }

  condition:
    any of them
}
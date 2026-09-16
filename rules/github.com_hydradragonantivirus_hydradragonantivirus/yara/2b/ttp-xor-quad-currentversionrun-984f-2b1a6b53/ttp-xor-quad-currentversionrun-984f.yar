rule TTP_XOR_QUAD_CurrentVersionRun_984f {
  strings:
    $key_984f = { cb 20 [2] ef 2e [2] c4 02 [2] ea 20 [2] fe 3b [2] f1 21 [2] ef 3c [2] ed 3d [2] f6 3b [2] ea 3c [2] f6 13 }

  condition:
    any of them
}
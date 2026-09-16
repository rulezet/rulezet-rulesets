rule TTP_XOR_QUAD_CurrentVersionRun_980b {
  strings:
    $key_980b = { cb 64 [2] ef 6a [2] c4 46 [2] ea 64 [2] fe 7f [2] f1 65 [2] ef 78 [2] ed 79 [2] f6 7f [2] ea 78 [2] f6 57 }

  condition:
    any of them
}
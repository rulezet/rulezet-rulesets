rule TTP_XOR_QUAD_CurrentVersionRun_987d {
  strings:
    $key_987d = { cb 12 [2] ef 1c [2] c4 30 [2] ea 12 [2] fe 09 [2] f1 13 [2] ef 0e [2] ed 0f [2] f6 09 [2] ea 0e [2] f6 21 }

  condition:
    any of them
}
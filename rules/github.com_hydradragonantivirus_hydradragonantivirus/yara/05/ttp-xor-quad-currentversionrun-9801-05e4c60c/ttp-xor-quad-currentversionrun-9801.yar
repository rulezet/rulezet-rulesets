rule TTP_XOR_QUAD_CurrentVersionRun_9801 {
  strings:
    $key_9801 = { cb 6e [2] ef 60 [2] c4 4c [2] ea 6e [2] fe 75 [2] f1 6f [2] ef 72 [2] ed 73 [2] f6 75 [2] ea 72 [2] f6 5d }

  condition:
    any of them
}
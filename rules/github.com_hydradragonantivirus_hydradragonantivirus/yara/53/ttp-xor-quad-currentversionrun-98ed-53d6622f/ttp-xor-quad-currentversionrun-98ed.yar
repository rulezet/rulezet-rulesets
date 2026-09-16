rule TTP_XOR_QUAD_CurrentVersionRun_98ed {
  strings:
    $key_98ed = { cb 82 [2] ef 8c [2] c4 a0 [2] ea 82 [2] fe 99 [2] f1 83 [2] ef 9e [2] ed 9f [2] f6 99 [2] ea 9e [2] f6 b1 }

  condition:
    any of them
}
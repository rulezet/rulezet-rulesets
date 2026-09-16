rule TTP_XOR_QUAD_CurrentVersionRun_9833 {
  strings:
    $key_9833 = { cb 5c [2] ef 52 [2] c4 7e [2] ea 5c [2] fe 47 [2] f1 5d [2] ef 40 [2] ed 41 [2] f6 47 [2] ea 40 [2] f6 6f }

  condition:
    any of them
}
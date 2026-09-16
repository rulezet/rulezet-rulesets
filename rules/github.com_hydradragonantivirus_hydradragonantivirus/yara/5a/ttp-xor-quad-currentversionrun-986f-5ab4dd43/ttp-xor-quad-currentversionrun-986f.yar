rule TTP_XOR_QUAD_CurrentVersionRun_986f {
  strings:
    $key_986f = { cb 00 [2] ef 0e [2] c4 22 [2] ea 00 [2] fe 1b [2] f1 01 [2] ef 1c [2] ed 1d [2] f6 1b [2] ea 1c [2] f6 33 }

  condition:
    any of them
}
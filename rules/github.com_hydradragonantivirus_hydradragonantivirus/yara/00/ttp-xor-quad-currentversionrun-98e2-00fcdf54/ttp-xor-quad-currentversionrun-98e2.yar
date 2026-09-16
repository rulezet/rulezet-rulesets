rule TTP_XOR_QUAD_CurrentVersionRun_98e2 {
  strings:
    $key_98e2 = { cb 8d [2] ef 83 [2] c4 af [2] ea 8d [2] fe 96 [2] f1 8c [2] ef 91 [2] ed 90 [2] f6 96 [2] ea 91 [2] f6 be }

  condition:
    any of them
}
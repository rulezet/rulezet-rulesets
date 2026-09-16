rule TTP_XOR_QUAD_CurrentVersionRun_845f {
  strings:
    $key_845f = { d7 30 [2] f3 3e [2] d8 12 [2] f6 30 [2] e2 2b [2] ed 31 [2] f3 2c [2] f1 2d [2] ea 2b [2] f6 2c [2] ea 03 }

  condition:
    any of them
}
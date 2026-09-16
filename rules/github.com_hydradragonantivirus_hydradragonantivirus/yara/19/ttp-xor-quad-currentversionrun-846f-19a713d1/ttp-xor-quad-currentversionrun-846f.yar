rule TTP_XOR_QUAD_CurrentVersionRun_846f {
  strings:
    $key_846f = { d7 00 [2] f3 0e [2] d8 22 [2] f6 00 [2] e2 1b [2] ed 01 [2] f3 1c [2] f1 1d [2] ea 1b [2] f6 1c [2] ea 33 }

  condition:
    any of them
}
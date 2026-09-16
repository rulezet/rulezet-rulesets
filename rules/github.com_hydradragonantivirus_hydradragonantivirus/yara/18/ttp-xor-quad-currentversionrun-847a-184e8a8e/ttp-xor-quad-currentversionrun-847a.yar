rule TTP_XOR_QUAD_CurrentVersionRun_847a {
  strings:
    $key_847a = { d7 15 [2] f3 1b [2] d8 37 [2] f6 15 [2] e2 0e [2] ed 14 [2] f3 09 [2] f1 08 [2] ea 0e [2] f6 09 [2] ea 26 }

  condition:
    any of them
}
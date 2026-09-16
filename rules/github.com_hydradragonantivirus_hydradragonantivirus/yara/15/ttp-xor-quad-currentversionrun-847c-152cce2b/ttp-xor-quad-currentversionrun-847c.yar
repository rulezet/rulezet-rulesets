rule TTP_XOR_QUAD_CurrentVersionRun_847c {
  strings:
    $key_847c = { d7 13 [2] f3 1d [2] d8 31 [2] f6 13 [2] e2 08 [2] ed 12 [2] f3 0f [2] f1 0e [2] ea 08 [2] f6 0f [2] ea 20 }

  condition:
    any of them
}
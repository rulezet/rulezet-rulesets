rule TTP_XOR_QUAD_CurrentVersionRun_847f {
  strings:
    $key_847f = { d7 10 [2] f3 1e [2] d8 32 [2] f6 10 [2] e2 0b [2] ed 11 [2] f3 0c [2] f1 0d [2] ea 0b [2] f6 0c [2] ea 23 }

  condition:
    any of them
}
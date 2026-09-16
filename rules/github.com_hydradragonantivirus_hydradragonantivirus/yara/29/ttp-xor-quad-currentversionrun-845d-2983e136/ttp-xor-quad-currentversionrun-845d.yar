rule TTP_XOR_QUAD_CurrentVersionRun_845d {
  strings:
    $key_845d = { d7 32 [2] f3 3c [2] d8 10 [2] f6 32 [2] e2 29 [2] ed 33 [2] f3 2e [2] f1 2f [2] ea 29 [2] f6 2e [2] ea 01 }

  condition:
    any of them
}
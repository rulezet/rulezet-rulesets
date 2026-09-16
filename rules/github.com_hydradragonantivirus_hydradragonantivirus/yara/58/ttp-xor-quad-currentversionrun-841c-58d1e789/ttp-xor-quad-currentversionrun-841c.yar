rule TTP_XOR_QUAD_CurrentVersionRun_841c {
  strings:
    $key_841c = { d7 73 [2] f3 7d [2] d8 51 [2] f6 73 [2] e2 68 [2] ed 72 [2] f3 6f [2] f1 6e [2] ea 68 [2] f6 6f [2] ea 40 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_842c {
  strings:
    $key_842c = { d7 43 [2] f3 4d [2] d8 61 [2] f6 43 [2] e2 58 [2] ed 42 [2] f3 5f [2] f1 5e [2] ea 58 [2] f6 5f [2] ea 70 }

  condition:
    any of them
}
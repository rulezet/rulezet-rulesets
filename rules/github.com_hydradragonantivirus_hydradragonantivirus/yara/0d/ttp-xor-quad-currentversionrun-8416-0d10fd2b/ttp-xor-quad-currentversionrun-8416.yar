rule TTP_XOR_QUAD_CurrentVersionRun_8416 {
  strings:
    $key_8416 = { d7 79 [2] f3 77 [2] d8 5b [2] f6 79 [2] e2 62 [2] ed 78 [2] f3 65 [2] f1 64 [2] ea 62 [2] f6 65 [2] ea 4a }

  condition:
    any of them
}
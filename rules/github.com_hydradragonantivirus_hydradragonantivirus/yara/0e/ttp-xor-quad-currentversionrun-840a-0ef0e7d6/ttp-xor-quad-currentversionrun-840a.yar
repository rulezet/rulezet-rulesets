rule TTP_XOR_QUAD_CurrentVersionRun_840a {
  strings:
    $key_840a = { d7 65 [2] f3 6b [2] d8 47 [2] f6 65 [2] e2 7e [2] ed 64 [2] f3 79 [2] f1 78 [2] ea 7e [2] f6 79 [2] ea 56 }

  condition:
    any of them
}
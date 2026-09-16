rule TTP_XOR_QUAD_CurrentVersionRun_840f {
  strings:
    $key_840f = { d7 60 [2] f3 6e [2] d8 42 [2] f6 60 [2] e2 7b [2] ed 61 [2] f3 7c [2] f1 7d [2] ea 7b [2] f6 7c [2] ea 53 }

  condition:
    any of them
}
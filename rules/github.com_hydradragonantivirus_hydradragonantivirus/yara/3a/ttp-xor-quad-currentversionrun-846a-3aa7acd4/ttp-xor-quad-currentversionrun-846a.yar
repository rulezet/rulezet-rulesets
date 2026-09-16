rule TTP_XOR_QUAD_CurrentVersionRun_846a {
  strings:
    $key_846a = { d7 05 [2] f3 0b [2] d8 27 [2] f6 05 [2] e2 1e [2] ed 04 [2] f3 19 [2] f1 18 [2] ea 1e [2] f6 19 [2] ea 36 }

  condition:
    any of them
}
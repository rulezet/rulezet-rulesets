rule TTP_XOR_QUAD_CurrentVersionRun_846d {
  strings:
    $key_846d = { d7 02 [2] f3 0c [2] d8 20 [2] f6 02 [2] e2 19 [2] ed 03 [2] f3 1e [2] f1 1f [2] ea 19 [2] f6 1e [2] ea 31 }

  condition:
    any of them
}
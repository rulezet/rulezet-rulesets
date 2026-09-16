rule TTP_XOR_QUAD_CurrentVersionRun_842e {
  strings:
    $key_842e = { d7 41 [2] f3 4f [2] d8 63 [2] f6 41 [2] e2 5a [2] ed 40 [2] f3 5d [2] f1 5c [2] ea 5a [2] f6 5d [2] ea 72 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_8471 {
  strings:
    $key_8471 = { d7 1e [2] f3 10 [2] d8 3c [2] f6 1e [2] e2 05 [2] ed 1f [2] f3 02 [2] f1 03 [2] ea 05 [2] f6 02 [2] ea 2d }

  condition:
    any of them
}
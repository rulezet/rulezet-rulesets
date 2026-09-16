rule TTP_XOR_QUAD_CurrentVersionRun_8432 {
  strings:
    $key_8432 = { d7 5d [2] f3 53 [2] d8 7f [2] f6 5d [2] e2 46 [2] ed 5c [2] f3 41 [2] f1 40 [2] ea 46 [2] f6 41 [2] ea 6e }

  condition:
    any of them
}
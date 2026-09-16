rule TTP_XOR_QUAD_CurrentVersionRun_8332 {
  strings:
    $key_8332 = { d0 5d [2] f4 53 [2] df 7f [2] f1 5d [2] e5 46 [2] ea 5c [2] f4 41 [2] f6 40 [2] ed 46 [2] f1 41 [2] ed 6e }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_837c {
  strings:
    $key_837c = { d0 13 [2] f4 1d [2] df 31 [2] f1 13 [2] e5 08 [2] ea 12 [2] f4 0f [2] f6 0e [2] ed 08 [2] f1 0f [2] ed 20 }

  condition:
    any of them
}
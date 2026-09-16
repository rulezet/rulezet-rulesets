rule TTP_XOR_QUAD_CurrentVersionRun_8366 {
  strings:
    $key_8366 = { d0 09 [2] f4 07 [2] df 2b [2] f1 09 [2] e5 12 [2] ea 08 [2] f4 15 [2] f6 14 [2] ed 12 [2] f1 15 [2] ed 3a }

  condition:
    any of them
}
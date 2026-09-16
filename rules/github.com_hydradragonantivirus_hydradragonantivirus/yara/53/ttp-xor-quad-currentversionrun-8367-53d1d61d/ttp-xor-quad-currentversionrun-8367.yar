rule TTP_XOR_QUAD_CurrentVersionRun_8367 {
  strings:
    $key_8367 = { d0 08 [2] f4 06 [2] df 2a [2] f1 08 [2] e5 13 [2] ea 09 [2] f4 14 [2] f6 15 [2] ed 13 [2] f1 14 [2] ed 3b }

  condition:
    any of them
}
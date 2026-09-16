rule TTP_XOR_QUAD_CurrentVersionRun_8362 {
  strings:
    $key_8362 = { d0 0d [2] f4 03 [2] df 2f [2] f1 0d [2] e5 16 [2] ea 0c [2] f4 11 [2] f6 10 [2] ed 16 [2] f1 11 [2] ed 3e }

  condition:
    any of them
}
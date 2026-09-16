rule TTP_XOR_QUAD_CurrentVersionRun_8322 {
  strings:
    $key_8322 = { d0 4d [2] f4 43 [2] df 6f [2] f1 4d [2] e5 56 [2] ea 4c [2] f4 51 [2] f6 50 [2] ed 56 [2] f1 51 [2] ed 7e }

  condition:
    any of them
}
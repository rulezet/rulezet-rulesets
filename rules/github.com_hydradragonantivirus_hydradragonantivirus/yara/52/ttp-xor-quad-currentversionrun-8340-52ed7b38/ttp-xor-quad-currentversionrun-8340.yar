rule TTP_XOR_QUAD_CurrentVersionRun_8340 {
  strings:
    $key_8340 = { d0 2f [2] f4 21 [2] df 0d [2] f1 2f [2] e5 34 [2] ea 2e [2] f4 33 [2] f6 32 [2] ed 34 [2] f1 33 [2] ed 1c }

  condition:
    any of them
}
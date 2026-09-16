rule TTP_XOR_QUAD_CurrentVersionRun_8341 {
  strings:
    $key_8341 = { d0 2e [2] f4 20 [2] df 0c [2] f1 2e [2] e5 35 [2] ea 2f [2] f4 32 [2] f6 33 [2] ed 35 [2] f1 32 [2] ed 1d }

  condition:
    any of them
}
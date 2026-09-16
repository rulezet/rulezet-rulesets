rule TTP_XOR_QUAD_CurrentVersionRun_8351 {
  strings:
    $key_8351 = { d0 3e [2] f4 30 [2] df 1c [2] f1 3e [2] e5 25 [2] ea 3f [2] f4 22 [2] f6 23 [2] ed 25 [2] f1 22 [2] ed 0d }

  condition:
    any of them
}
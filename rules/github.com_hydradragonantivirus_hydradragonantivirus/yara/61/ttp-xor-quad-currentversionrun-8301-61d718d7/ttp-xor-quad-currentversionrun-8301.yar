rule TTP_XOR_QUAD_CurrentVersionRun_8301 {
  strings:
    $key_8301 = { d0 6e [2] f4 60 [2] df 4c [2] f1 6e [2] e5 75 [2] ea 6f [2] f4 72 [2] f6 73 [2] ed 75 [2] f1 72 [2] ed 5d }

  condition:
    any of them
}
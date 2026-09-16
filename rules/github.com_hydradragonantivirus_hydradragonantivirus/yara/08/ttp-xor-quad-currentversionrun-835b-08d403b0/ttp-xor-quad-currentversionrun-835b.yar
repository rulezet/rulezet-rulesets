rule TTP_XOR_QUAD_CurrentVersionRun_835b {
  strings:
    $key_835b = { d0 34 [2] f4 3a [2] df 16 [2] f1 34 [2] e5 2f [2] ea 35 [2] f4 28 [2] f6 29 [2] ed 2f [2] f1 28 [2] ed 07 }

  condition:
    any of them
}
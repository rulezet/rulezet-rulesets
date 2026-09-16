rule TTP_XOR_QUAD_CurrentVersionRun_830b {
  strings:
    $key_830b = { d0 64 [2] f4 6a [2] df 46 [2] f1 64 [2] e5 7f [2] ea 65 [2] f4 78 [2] f6 79 [2] ed 7f [2] f1 78 [2] ed 57 }

  condition:
    any of them
}
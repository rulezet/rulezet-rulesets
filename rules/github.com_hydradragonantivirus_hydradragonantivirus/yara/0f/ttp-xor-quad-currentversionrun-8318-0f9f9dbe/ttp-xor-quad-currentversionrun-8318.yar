rule TTP_XOR_QUAD_CurrentVersionRun_8318 {
  strings:
    $key_8318 = { d0 77 [2] f4 79 [2] df 55 [2] f1 77 [2] e5 6c [2] ea 76 [2] f4 6b [2] f6 6a [2] ed 6c [2] f1 6b [2] ed 44 }

  condition:
    any of them
}
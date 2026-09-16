rule TTP_XOR_QUAD_CurrentVersionRun_8308 {
  strings:
    $key_8308 = { d0 67 [2] f4 69 [2] df 45 [2] f1 67 [2] e5 7c [2] ea 66 [2] f4 7b [2] f6 7a [2] ed 7c [2] f1 7b [2] ed 54 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_8335 {
  strings:
    $key_8335 = { d0 5a [2] f4 54 [2] df 78 [2] f1 5a [2] e5 41 [2] ea 5b [2] f4 46 [2] f6 47 [2] ed 41 [2] f1 46 [2] ed 69 }

  condition:
    any of them
}
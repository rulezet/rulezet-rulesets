rule TTP_XOR_QUAD_CurrentVersionRun_83f9 {
  strings:
    $key_83f9 = { d0 96 [2] f4 98 [2] df b4 [2] f1 96 [2] e5 8d [2] ea 97 [2] f4 8a [2] f6 8b [2] ed 8d [2] f1 8a [2] ed a5 }

  condition:
    any of them
}
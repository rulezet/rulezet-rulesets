rule TTP_XOR_QUAD_CurrentVersionRun_834a {
  strings:
    $key_834a = { d0 25 [2] f4 2b [2] df 07 [2] f1 25 [2] e5 3e [2] ea 24 [2] f4 39 [2] f6 38 [2] ed 3e [2] f1 39 [2] ed 16 }

  condition:
    any of them
}
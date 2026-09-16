rule TTP_XOR_QUAD_CurrentVersionRun_834f {
  strings:
    $key_834f = { d0 20 [2] f4 2e [2] df 02 [2] f1 20 [2] e5 3b [2] ea 21 [2] f4 3c [2] f6 3d [2] ed 3b [2] f1 3c [2] ed 13 }

  condition:
    any of them
}
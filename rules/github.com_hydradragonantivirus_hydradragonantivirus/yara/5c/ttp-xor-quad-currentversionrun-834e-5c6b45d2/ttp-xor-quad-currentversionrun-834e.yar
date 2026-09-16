rule TTP_XOR_QUAD_CurrentVersionRun_834e {
  strings:
    $key_834e = { d0 21 [2] f4 2f [2] df 03 [2] f1 21 [2] e5 3a [2] ea 20 [2] f4 3d [2] f6 3c [2] ed 3a [2] f1 3d [2] ed 12 }

  condition:
    any of them
}
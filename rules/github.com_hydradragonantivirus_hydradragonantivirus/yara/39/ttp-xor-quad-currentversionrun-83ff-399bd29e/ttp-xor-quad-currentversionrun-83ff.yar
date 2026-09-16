rule TTP_XOR_QUAD_CurrentVersionRun_83ff {
  strings:
    $key_83ff = { d0 90 [2] f4 9e [2] df b2 [2] f1 90 [2] e5 8b [2] ea 91 [2] f4 8c [2] f6 8d [2] ed 8b [2] f1 8c [2] ed a3 }

  condition:
    any of them
}
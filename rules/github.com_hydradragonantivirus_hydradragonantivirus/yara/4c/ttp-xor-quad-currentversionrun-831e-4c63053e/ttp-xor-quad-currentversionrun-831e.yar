rule TTP_XOR_QUAD_CurrentVersionRun_831e {
  strings:
    $key_831e = { d0 71 [2] f4 7f [2] df 53 [2] f1 71 [2] e5 6a [2] ea 70 [2] f4 6d [2] f6 6c [2] ed 6a [2] f1 6d [2] ed 42 }

  condition:
    any of them
}
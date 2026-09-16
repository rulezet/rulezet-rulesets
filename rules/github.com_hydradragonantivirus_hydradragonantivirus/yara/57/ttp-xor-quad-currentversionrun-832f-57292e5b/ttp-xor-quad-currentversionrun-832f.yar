rule TTP_XOR_QUAD_CurrentVersionRun_832f {
  strings:
    $key_832f = { d0 40 [2] f4 4e [2] df 62 [2] f1 40 [2] e5 5b [2] ea 41 [2] f4 5c [2] f6 5d [2] ed 5b [2] f1 5c [2] ed 73 }

  condition:
    any of them
}
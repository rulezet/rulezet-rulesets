rule TTP_XOR_QUAD_CurrentVersionRun_831c {
  strings:
    $key_831c = { d0 73 [2] f4 7d [2] df 51 [2] f1 73 [2] e5 68 [2] ea 72 [2] f4 6f [2] f6 6e [2] ed 68 [2] f1 6f [2] ed 40 }

  condition:
    any of them
}
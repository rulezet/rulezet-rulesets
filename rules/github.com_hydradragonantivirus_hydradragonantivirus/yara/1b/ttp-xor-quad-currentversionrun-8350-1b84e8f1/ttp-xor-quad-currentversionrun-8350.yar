rule TTP_XOR_QUAD_CurrentVersionRun_8350 {
  strings:
    $key_8350 = { d0 3f [2] f4 31 [2] df 1d [2] f1 3f [2] e5 24 [2] ea 3e [2] f4 23 [2] f6 22 [2] ed 24 [2] f1 23 [2] ed 0c }

  condition:
    any of them
}
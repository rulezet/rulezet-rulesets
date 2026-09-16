rule TTP_XOR_QUAD_CurrentVersionRun_8330 {
  strings:
    $key_8330 = { d0 5f [2] f4 51 [2] df 7d [2] f1 5f [2] e5 44 [2] ea 5e [2] f4 43 [2] f6 42 [2] ed 44 [2] f1 43 [2] ed 6c }

  condition:
    any of them
}
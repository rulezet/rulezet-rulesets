rule TTP_XOR_QUAD_CurrentVersionRun_832c {
  strings:
    $key_832c = { d0 43 [2] f4 4d [2] df 61 [2] f1 43 [2] e5 58 [2] ea 42 [2] f4 5f [2] f6 5e [2] ed 58 [2] f1 5f [2] ed 70 }

  condition:
    any of them
}
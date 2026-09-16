rule TTP_XOR_QUAD_CurrentVersionRun_9a5d {
  strings:
    $key_9a5d = { c9 32 [2] ed 3c [2] c6 10 [2] e8 32 [2] fc 29 [2] f3 33 [2] ed 2e [2] ef 2f [2] f4 29 [2] e8 2e [2] f4 01 }

  condition:
    any of them
}
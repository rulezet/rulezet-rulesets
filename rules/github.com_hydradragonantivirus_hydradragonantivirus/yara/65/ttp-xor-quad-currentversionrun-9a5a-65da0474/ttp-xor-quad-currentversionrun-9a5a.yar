rule TTP_XOR_QUAD_CurrentVersionRun_9a5a {
  strings:
    $key_9a5a = { c9 35 [2] ed 3b [2] c6 17 [2] e8 35 [2] fc 2e [2] f3 34 [2] ed 29 [2] ef 28 [2] f4 2e [2] e8 29 [2] f4 06 }

  condition:
    any of them
}
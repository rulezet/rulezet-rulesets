rule TTP_XOR_QUAD_CurrentVersionRun_9a4a {
  strings:
    $key_9a4a = { c9 25 [2] ed 2b [2] c6 07 [2] e8 25 [2] fc 3e [2] f3 24 [2] ed 39 [2] ef 38 [2] f4 3e [2] e8 39 [2] f4 16 }

  condition:
    any of them
}
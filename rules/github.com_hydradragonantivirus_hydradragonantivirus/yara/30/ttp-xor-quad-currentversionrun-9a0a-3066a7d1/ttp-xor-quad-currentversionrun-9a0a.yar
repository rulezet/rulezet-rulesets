rule TTP_XOR_QUAD_CurrentVersionRun_9a0a {
  strings:
    $key_9a0a = { c9 65 [2] ed 6b [2] c6 47 [2] e8 65 [2] fc 7e [2] f3 64 [2] ed 79 [2] ef 78 [2] f4 7e [2] e8 79 [2] f4 56 }

  condition:
    any of them
}
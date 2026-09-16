rule TTP_XOR_QUAD_CurrentVersionRun_9a2a {
  strings:
    $key_9a2a = { c9 45 [2] ed 4b [2] c6 67 [2] e8 45 [2] fc 5e [2] f3 44 [2] ed 59 [2] ef 58 [2] f4 5e [2] e8 59 [2] f4 76 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9a7c {
  strings:
    $key_9a7c = { c9 13 [2] ed 1d [2] c6 31 [2] e8 13 [2] fc 08 [2] f3 12 [2] ed 0f [2] ef 0e [2] f4 08 [2] e8 0f [2] f4 20 }

  condition:
    any of them
}
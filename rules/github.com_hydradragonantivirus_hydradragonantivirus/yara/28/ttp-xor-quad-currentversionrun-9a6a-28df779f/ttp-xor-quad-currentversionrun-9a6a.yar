rule TTP_XOR_QUAD_CurrentVersionRun_9a6a {
  strings:
    $key_9a6a = { c9 05 [2] ed 0b [2] c6 27 [2] e8 05 [2] fc 1e [2] f3 04 [2] ed 19 [2] ef 18 [2] f4 1e [2] e8 19 [2] f4 36 }

  condition:
    any of them
}
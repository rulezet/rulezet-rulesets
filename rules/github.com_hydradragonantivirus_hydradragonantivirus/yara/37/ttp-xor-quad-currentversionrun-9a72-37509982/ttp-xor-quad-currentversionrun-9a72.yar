rule TTP_XOR_QUAD_CurrentVersionRun_9a72 {
  strings:
    $key_9a72 = { c9 1d [2] ed 13 [2] c6 3f [2] e8 1d [2] fc 06 [2] f3 1c [2] ed 01 [2] ef 00 [2] f4 06 [2] e8 01 [2] f4 2e }

  condition:
    any of them
}
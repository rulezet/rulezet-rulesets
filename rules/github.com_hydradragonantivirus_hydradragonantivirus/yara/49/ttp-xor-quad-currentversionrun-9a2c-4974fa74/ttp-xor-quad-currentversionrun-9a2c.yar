rule TTP_XOR_QUAD_CurrentVersionRun_9a2c {
  strings:
    $key_9a2c = { c9 43 [2] ed 4d [2] c6 61 [2] e8 43 [2] fc 58 [2] f3 42 [2] ed 5f [2] ef 5e [2] f4 58 [2] e8 5f [2] f4 70 }

  condition:
    any of them
}
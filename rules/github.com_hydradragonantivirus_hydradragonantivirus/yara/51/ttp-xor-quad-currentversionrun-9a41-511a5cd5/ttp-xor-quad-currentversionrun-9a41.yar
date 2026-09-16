rule TTP_XOR_QUAD_CurrentVersionRun_9a41 {
  strings:
    $key_9a41 = { c9 2e [2] ed 20 [2] c6 0c [2] e8 2e [2] fc 35 [2] f3 2f [2] ed 32 [2] ef 33 [2] f4 35 [2] e8 32 [2] f4 1d }

  condition:
    any of them
}
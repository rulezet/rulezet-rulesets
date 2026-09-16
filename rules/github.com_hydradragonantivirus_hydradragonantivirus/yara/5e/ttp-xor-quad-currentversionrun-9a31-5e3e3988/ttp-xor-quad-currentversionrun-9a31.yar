rule TTP_XOR_QUAD_CurrentVersionRun_9a31 {
  strings:
    $key_9a31 = { c9 5e [2] ed 50 [2] c6 7c [2] e8 5e [2] fc 45 [2] f3 5f [2] ed 42 [2] ef 43 [2] f4 45 [2] e8 42 [2] f4 6d }

  condition:
    any of them
}
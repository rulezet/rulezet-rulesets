rule TTP_XOR_QUAD_CurrentVersionRun_9a21 {
  strings:
    $key_9a21 = { c9 4e [2] ed 40 [2] c6 6c [2] e8 4e [2] fc 55 [2] f3 4f [2] ed 52 [2] ef 53 [2] f4 55 [2] e8 52 [2] f4 7d }

  condition:
    any of them
}
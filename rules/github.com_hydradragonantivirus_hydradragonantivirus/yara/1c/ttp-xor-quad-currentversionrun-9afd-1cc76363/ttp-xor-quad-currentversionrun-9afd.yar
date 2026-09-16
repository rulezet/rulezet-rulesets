rule TTP_XOR_QUAD_CurrentVersionRun_9afd {
  strings:
    $key_9afd = { c9 92 [2] ed 9c [2] c6 b0 [2] e8 92 [2] fc 89 [2] f3 93 [2] ed 8e [2] ef 8f [2] f4 89 [2] e8 8e [2] f4 a1 }

  condition:
    any of them
}
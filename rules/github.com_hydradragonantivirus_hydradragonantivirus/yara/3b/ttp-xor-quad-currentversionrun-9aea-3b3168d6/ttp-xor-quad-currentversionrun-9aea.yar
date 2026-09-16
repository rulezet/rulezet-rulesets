rule TTP_XOR_QUAD_CurrentVersionRun_9aea {
  strings:
    $key_9aea = { c9 85 [2] ed 8b [2] c6 a7 [2] e8 85 [2] fc 9e [2] f3 84 [2] ed 99 [2] ef 98 [2] f4 9e [2] e8 99 [2] f4 b6 }

  condition:
    any of them
}
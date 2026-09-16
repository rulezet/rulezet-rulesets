rule TTP_XOR_QUAD_CurrentVersionRun_95ea {
  strings:
    $key_95ea = { c6 85 [2] e2 8b [2] c9 a7 [2] e7 85 [2] f3 9e [2] fc 84 [2] e2 99 [2] e0 98 [2] fb 9e [2] e7 99 [2] fb b6 }

  condition:
    any of them
}
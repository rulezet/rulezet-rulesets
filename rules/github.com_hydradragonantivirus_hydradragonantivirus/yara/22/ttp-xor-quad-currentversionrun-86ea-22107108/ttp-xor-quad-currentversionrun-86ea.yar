rule TTP_XOR_QUAD_CurrentVersionRun_86ea {
  strings:
    $key_86ea = { d5 85 [2] f1 8b [2] da a7 [2] f4 85 [2] e0 9e [2] ef 84 [2] f1 99 [2] f3 98 [2] e8 9e [2] f4 99 [2] e8 b6 }

  condition:
    any of them
}
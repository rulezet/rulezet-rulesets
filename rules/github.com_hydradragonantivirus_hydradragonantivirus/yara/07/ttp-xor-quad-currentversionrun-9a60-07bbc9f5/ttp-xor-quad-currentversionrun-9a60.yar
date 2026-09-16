rule TTP_XOR_QUAD_CurrentVersionRun_9a60 {
  strings:
    $key_9a60 = { c9 0f [2] ed 01 [2] c6 2d [2] e8 0f [2] fc 14 [2] f3 0e [2] ed 13 [2] ef 12 [2] f4 14 [2] e8 13 [2] f4 3c }

  condition:
    any of them
}
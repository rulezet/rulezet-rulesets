rule TTP_XOR_QUAD_CurrentVersionRun_9a2d {
  strings:
    $key_9a2d = { c9 42 [2] ed 4c [2] c6 60 [2] e8 42 [2] fc 59 [2] f3 43 [2] ed 5e [2] ef 5f [2] f4 59 [2] e8 5e [2] f4 71 }

  condition:
    any of them
}